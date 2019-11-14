// Copyright 2018 The Grin Developers
// Modifications Copyright 2019 The Gotts Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Grin wallet command-line function implementations

use crate::util::{Mutex, ZeroingString};
use chrono::NaiveDateTime as DateTime;
use colored::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{stdin, stdout, Read, Write};
use std::sync::mpsc::channel;
use std::sync::mpsc::TryRecvError;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json as json;
use uuid::Uuid;

use crate::api::TLSConfig;
use crate::core::core;
use crate::keychain;

use crate::config::{GrinRelayConfig, WalletConfig};
use crate::error::{Error, ErrorKind};
use crate::impls::{
	instantiate_wallet, FileWalletCommAdapter, GrinrelayWalletCommAdapter, HTTPWalletCommAdapter,
	KeybaseWalletCommAdapter, LMDBBackend, NullWalletCommAdapter,
};
use crate::impls::{HTTPNodeClient, WalletSeed};
use crate::libwallet::{
	InitTxArgs, IssueInvoiceTxArgs, Listener, NodeClient, OutputStatus, TxLogEntryType, TxProof,
	WalletInst,
};
use crate::{controller, display};

/// Arguments common to all wallet commands
#[derive(Clone)]
pub struct GlobalArgs {
	pub account: String,
	pub node_api_secret: Option<String>,
	pub show_spent: bool,
	pub password: Option<ZeroingString>,
	pub tls_conf: Option<TLSConfig>,
}

/// Arguments for init command
pub struct InitArgs {
	/// BIP39 recovery phrase length
	pub list_length: usize,
	pub password: ZeroingString,
	pub config: WalletConfig,
	pub recovery_phrase: Option<ZeroingString>,
	pub restore: bool,
}

pub fn init(g_args: &GlobalArgs, args: InitArgs) -> Result<(), Error> {
	WalletSeed::init_file(
		args.config.data_file_dir.as_str(),
		args.list_length,
		args.recovery_phrase,
		&args.password,
		true,
	)?;
	info!("Wallet seed file created");
	let client_n = HTTPNodeClient::new(
		&args.config.check_node_api_http_addr,
		g_args.node_api_secret.clone(),
	);
	let _: LMDBBackend<HTTPNodeClient, keychain::ExtKeychain> =
		LMDBBackend::new(args.config.clone(), &args.password, client_n)?;
	info!("Wallet database backend created");
	Ok(())
}

/// Argument for recover
pub struct RecoverArgs {
	pub recovery_phrase: Option<ZeroingString>,
	pub passphrase: ZeroingString,
}

pub fn recover(config: &WalletConfig, args: RecoverArgs) -> Result<(), Error> {
	if args.recovery_phrase.is_none() {
		let res = WalletSeed::from_file(config.data_file_dir.as_str(), &args.passphrase);
		if let Err(e) = res {
			error!("Error loading wallet seed (check password): {}", e);
			return Err(e.into());
		}
		let _ = res.unwrap().show_recovery_phrase();
	} else {
		let res = WalletSeed::recover_from_phrase(
			config.data_file_dir.as_str(),
			&args.recovery_phrase.as_ref().unwrap(),
			&args.passphrase,
		);
		if let Err(e) = res {
			error!("Error recovering seed - {}", e);
			return Err(e.into());
		}
	}
	Ok(())
}

/// Arguments for listen command
pub struct ListenArgs {
	pub method: String,
}

pub fn listen(config: &WalletConfig, args: &ListenArgs, g_args: &GlobalArgs) -> Result<(), Error> {
	let mut params = HashMap::new();
	params.insert("api_listen_addr".to_owned(), config.api_listen_addr());
	if let Some(t) = g_args.tls_conf.as_ref() {
		params.insert("certificate".to_owned(), t.certificate.clone());
		params.insert("private_key".to_owned(), t.private_key.clone());
	}
	let res = match args.method.as_str() {
		"http" => {
			// HTTP adapter can't use the listen trait method because of the
			// crate structure. May be able to fix when V1 API is deprecated
			let node_client = HTTPNodeClient::new(
				&config.check_node_api_http_addr,
				g_args.node_api_secret.clone(),
			);
			let wallet = instantiate_wallet(
				config.clone(),
				node_client,
				&g_args.password.clone().unwrap(),
				&g_args.account,
			)?;
			let listen_addr = params.get("api_listen_addr").unwrap();
			let tls_conf = match params.get("certificate") {
				Some(s) => Some(TLSConfig::new(
					s.to_owned(),
					params.get("private_key").unwrap().to_owned(),
				)),
				None => None,
			};

			let grinrelay_config = config.grinrelay_config.clone().unwrap_or_default();
			let (grinrelay_key_path, relay_rx, grinrelay_listener) =
				if grinrelay_config.enable_grinrelay {
					// The streaming channel between 'grinrelay_listener' and 'foreign_listener'
					let (relay_tx_as_payee, relay_rx) = channel();

					let (grinrelay_key_path, grinrelay_listener) = controller::grinrelay_listener(
						wallet.clone(),
						config.grinrelay_config.clone().unwrap_or_default(),
						None,
						Some(relay_tx_as_payee),
						None,
					)?;

					(
						Some(grinrelay_key_path),
						Some(relay_rx),
						Some(grinrelay_listener),
					)
				} else {
					(None, None, None)
				};

			controller::foreign_listener(
				wallet.clone(),
				&listen_addr,
				tls_conf,
				relay_rx,
				grinrelay_listener,
				grinrelay_key_path,
				&g_args.account,
			)?;
			Ok(())
		}
		"keybase" => {
			let adapter = KeybaseWalletCommAdapter::new();
			adapter.listen(
				params,
				config.clone(),
				&g_args.password.clone().unwrap(),
				&g_args.account,
				g_args.node_api_secret.clone(),
			)
		}
		_ => Ok(()),
	};

	if let Err(e) = res {
		return Err(ErrorKind::LibWallet(e.kind(), e.cause_string()).into());
	}
	Ok(())
}

pub fn owner_api(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	config: &WalletConfig,
	g_args: &GlobalArgs,
) -> Result<(), Error> {
	let res = controller::owner_listener(
		wallet,
		config.owner_api_listen_addr().as_str(),
		g_args.node_api_secret.clone(),
		g_args.tls_conf.clone(),
		config.owner_api_include_foreign.clone(),
	);
	if let Err(e) = res {
		return Err(ErrorKind::LibWallet(e.kind(), e.cause_string()).into());
	}
	Ok(())
}

/// Arguments for account command
pub struct AccountArgs {
	pub create: Option<String>,
}

pub fn account(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	args: AccountArgs,
) -> Result<(), Error> {
	if args.create.is_none() {
		let res = controller::owner_single_use(wallet, |api| {
			let acct_mappings = api.accounts()?;
			// give logging thread a moment to catch up
			thread::sleep(Duration::from_millis(200));
			display::accounts(acct_mappings);
			Ok(())
		});
		if let Err(e) = res {
			error!("Error listing accounts: {}", e);
			return Err(ErrorKind::LibWallet(e.kind(), e.cause_string()).into());
		}
	} else {
		let label = args.create.unwrap();
		let res = controller::owner_single_use(wallet, |api| {
			api.create_account_path(&label)?;
			thread::sleep(Duration::from_millis(200));
			info!("Account: '{}' Created!", label);
			Ok(())
		});
		if let Err(e) = res {
			thread::sleep(Duration::from_millis(200));
			error!("Error creating account '{}': {}", label, e);
			return Err(ErrorKind::LibWallet(e.kind(), e.cause_string()).into());
		}
	}
	Ok(())
}

/// Arguments for the send command
pub struct SendArgs {
	pub amount: u64,
	pub message: Option<String>,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub estimate_selection_strategies: bool,
	pub method: String,
	pub dest: String,
	pub change_outputs: usize,
	pub fluff: bool,
	pub max_outputs: usize,
	pub target_slate_version: Option<u16>,
}

/// Prompts for a password on STDOUT and reads it from STDIN
pub fn prompt_relayaddr_stdout(relay_addr: &str) -> std::io::Result<String> {
	let mut s = String::new();
	write!(
		stdout(),
		"One online address matched: {}\n",
		relay_addr.bright_blue()
	)?;

	write!(
		stdout(),
		"Do you confirm this is the correct address and continue to send? [{}]: ",
		"y/N".bright_blue(),
	)?;

	let _ = stdout().flush();
	stdin()
		.read_line(&mut s)
		.expect("Did not enter a correct string");
	if let Some('\n') = s.chars().next_back() {
		s.pop();
	}
	if let Some('\r') = s.chars().next_back() {
		s.pop();
	}

	Ok(s)
}

pub fn send(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	args: SendArgs,
	wallet_config: &WalletConfig,
) -> Result<(), Error> {
	let dark_scheme = wallet_config.dark_background_color_scheme.unwrap_or(true);

	// The streaming channel between 'grinrelay_listener' and 'GrinrelayWalletCommAdapter'
	let (relay_tx_as_payer, relay_rx) = channel();

	let mut grinrelay_listener: Option<Box<Listener>> = None;
	let mut grinrelay_key_path: Option<u64> = None;
	let mut dest = args.dest.clone();

	if "relay" == args.method.as_str() {
		let (relay_addr_query_sender, relay_addr_query_rx) = channel();

		// Start a Grin Relay service firstly
		let (key_path, listener) = controller::grinrelay_listener(
			wallet.clone(),
			wallet_config.grinrelay_config.clone().unwrap_or_default(),
			Some(relay_tx_as_payer),
			None,
			Some(relay_addr_query_sender),
		)?;

		// Wait for connecting with relay service
		let mut wait_time = 0;
		while !listener.is_connected() {
			thread::sleep(Duration::from_millis(100));
			wait_time += 1;
			if wait_time > 50 {
				println!(
					"{} to connect with grin relay service, 5s timeout. please try again later",
					"Fail".bright_red(),
				);
				std::process::exit(1);
			}
		}
		grinrelay_listener = Some(listener.clone());
		grinrelay_key_path = Some(key_path);

		// Conversion the abbreviation address to the full address
		if 6 == dest.len() {
			let abbr = dest.clone();
			if listener.retrieve_relay_addr(abbr).is_err() {
				println!(
					"{} {}",
					"Fail".bright_red(),
					"to send query request for abbreviated relay addr!\n"
				);
				std::process::exit(1);
			}

			const TTL: u16 = 10;
			let mut addresses: Option<Vec<String>> = None;
			let mut cnt = 0;
			loop {
				match relay_addr_query_rx.try_recv() {
					Ok((_abbr, addrs)) => {
						if !addrs.is_empty() {
							addresses = Some(addrs);
						}
						break;
					}
					Err(TryRecvError::Disconnected) => break,
					Err(TryRecvError::Empty) => {}
				}
				cnt += 1;
				if cnt > TTL * 10 {
					info!(
						"{} from relay server for address query. {}s timeout",
						"No response".bright_blue(),
						TTL
					);
					return Err(ErrorKind::GenericError(
						"relay server no response, please try again later".into(),
					))?;
				}
				thread::sleep(Duration::from_millis(100));
			}

			if let Some(addresses) = addresses {
				match addresses.len() {
					0 => {
						return Err(ErrorKind::ArgumentError(
							"wrong address, or destination is offline".into(),
						))?;
					}
					1 => {
						dest = addresses.first().unwrap().clone();
						let result = prompt_relayaddr_stdout(dest.as_str());
						let ret_str = result.unwrap();

						if "y" != ret_str && "Y" != ret_str {
							println!("{}", "Send Cancelled\n".bright_yellow());
							std::process::exit(1);
						}
					}
					_ => {
						println!("{} because of risk for abbreviated address conflict. Please use the full address instead of the short abbr addr", "Send Cancelled".bright_yellow());
						println!(
							"{} addresses matched the same abbreviation address: {:?}",
							addresses.len().to_string().bright_red(),
							addresses,
						);
						std::process::exit(1);
					}
				}
			} else {
				return Err(ErrorKind::ArgumentError(
					"wrong address, or destination is offline".into(),
				))?;
			}
		}
	}

	controller::owner_single_use(wallet.clone(), |api| {
		if args.estimate_selection_strategies {
			let strategies = vec!["smallest", "biggest", "all"]
				.into_iter()
				.map(|strategy| {
					let init_args = InitTxArgs {
						src_acct_name: None,
						amount: args.amount,
						minimum_confirmations: args.minimum_confirmations,
						max_outputs: args.max_outputs as u32,
						num_change_outputs: args.change_outputs as u32,
						selection_strategy: strategy.to_owned(),
						estimate_only: Some(true),
						..Default::default()
					};
					let slate = api.init_send_tx(init_args).unwrap();
					(strategy, slate.amount, slate.fee)
				})
				.collect();
			display::estimate(args.amount, strategies, dark_scheme);
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: args.amount,
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs as u32,
				num_change_outputs: args.change_outputs as u32,
				selection_strategy: args.selection_strategy.clone(),
				message: args.message.clone(),
				target_slate_version: args.target_slate_version,
				send_args: None,
				..Default::default()
			};
			let result = api.init_send_tx(init_args);
			let mut slate = match result {
				Ok(s) => {
					info!(
						"Tx created: {} grin to {} (strategy '{}')",
						core::amount_to_hr_string(args.amount, false),
						args.dest,
						args.selection_strategy.clone(),
					);
					s
				}
				Err(e) => {
					info!("Tx not created: {}", e);
					return Err(e);
				}
			};
			let adapter = match args.method.as_str() {
				"http" => HTTPWalletCommAdapter::new(),
				"file" => FileWalletCommAdapter::new(),
				"relay" => GrinrelayWalletCommAdapter::new(grinrelay_listener.unwrap(), relay_rx),
				"keybase" => KeybaseWalletCommAdapter::new(),
				"self" => NullWalletCommAdapter::new(),
				_ => NullWalletCommAdapter::new(),
			};

			if adapter.supports_sync() {
				let (returned_slate, tx_proof) = adapter.send_tx_sync(dest.as_str(), &slate)?;
				slate = returned_slate;
				api.tx_lock_outputs(&slate, 0)?;
				if args.method == "self" {
					controller::foreign_single_use(wallet, |api| {
						slate = api.receive_tx(&slate, Some(&args.dest), None, None)?;
						Ok(())
					})?;
				}
				if let Err(e) = api.verify_slate_messages(&slate) {
					error!("Error validating participant messages: {}", e);
					return Err(e);
				}
				slate = api.finalize_tx(&slate, tx_proof, grinrelay_key_path)?;
			} else {
				adapter.send_tx_async(dest.as_str(), &slate)?;
				api.tx_lock_outputs(&slate, 0)?;
			}
			if adapter.supports_sync() {
				let result = api.post_tx(Some(slate.id), &slate.tx, args.fluff);
				match result {
					Ok(_) => {
						info!("Tx sent ok",);
						return Ok(());
					}
					Err(e) => {
						// re-post last unconfirmed txs and try again
						if let Ok(true) = api.repost_last_txs(args.fluff, false) {
							// iff one re-post success, post this transaction again
							if let Ok(_) = api.post_tx(Some(slate.id), &slate.tx, args.fluff) {
								info!("Tx sent ok (with last unconfirmed tx/s re-post)");
								return Ok(());
							}
						}

						error!("Tx sent fail on post.");
						let _ = api.cancel_tx(None, Some(slate.id));
						return Err(e);
					}
				}
			}
		}
		Ok(())
	})?;
	Ok(())
}

/// Receive command argument
pub struct ReceiveArgs {
	pub input: String,
	pub message: Option<String>,
}

pub fn receive(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	g_args: &GlobalArgs,
	args: ReceiveArgs,
) -> Result<(), Error> {
	let adapter = FileWalletCommAdapter::new();
	let mut slate = adapter.receive_tx_async(&args.input)?;
	controller::foreign_single_use(wallet, |api| {
		if let Err(e) = api.verify_slate_messages(&slate) {
			error!("Error validating participant messages: {}", e);
			return Err(e);
		}
		slate = api.receive_tx(&slate, Some(&g_args.account), args.message.clone(), None)?;
		Ok(())
	})?;
	let send_tx = format!("{}.response", args.input);
	adapter.send_tx_async(&send_tx, &slate)?;
	info!(
		"Response file {}.response generated, and can be sent back to the transaction originator.",
		args.input
	);
	Ok(())
}

/// Finalize command args
pub struct FinalizeArgs {
	pub input: String,
	pub fluff: bool,
}

pub fn finalize(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	args: FinalizeArgs,
) -> Result<(), Error> {
	let adapter = FileWalletCommAdapter::new();
	let mut slate = adapter.receive_tx_async(&args.input)?;
	// Rather than duplicating the entire command, we'll just
	// try to determine what kind of finalization this is
	// based on the slate contents
	// for now, we can tell this is an invoice transaction
	// if the receipient (participant 1) hasn't completed sigs
	let part_data = slate.participant_with_id(1);
	let is_invoice = {
		match part_data {
			None => {
				error!("Expected slate participant data missing");
				return Err(ErrorKind::ArgumentError(
					"Expected Slate participant data missing".into(),
				))?;
			}
			Some(p) => !p.is_complete(),
		}
	};

	if is_invoice {
		controller::foreign_single_use(wallet.clone(), |api| {
			if let Err(e) = api.verify_slate_messages(&slate) {
				error!("Error validating participant messages: {}", e);
				return Err(e);
			}
			slate = api.finalize_invoice_tx(&mut slate)?;
			Ok(())
		})?;
	} else {
		controller::owner_single_use(wallet.clone(), |api| {
			if let Err(e) = api.verify_slate_messages(&slate) {
				error!("Error validating participant messages: {}", e);
				return Err(e);
			}
			slate = api.finalize_tx(&mut slate, None, None)?;
			Ok(())
		})?;
	}

	controller::owner_single_use(wallet.clone(), |api| {
		let result = api.post_tx(Some(slate.id), &slate.tx, args.fluff);
		match result {
			Ok(_) => {
				info!("Transaction sent successfully, check the wallet again for confirmation.");
				Ok(())
			}
			Err(e) => {
				error!("Tx not sent: {}", e);
				Err(e)
			}
		}
	})?;

	Ok(())
}

/// Issue Invoice Args
pub struct IssueInvoiceArgs {
	/// output file
	pub dest: String,
	/// issue invoice tx args
	pub issue_args: IssueInvoiceTxArgs,
}

pub fn issue_invoice_tx(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	args: IssueInvoiceArgs,
) -> Result<(), Error> {
	controller::owner_single_use(wallet.clone(), |api| {
		let slate = api.issue_invoice_tx(args.issue_args)?;
		let mut tx_file = File::create(args.dest.clone())?;
		tx_file.write_all(json::to_string(&slate).unwrap().as_bytes())?;
		tx_file.sync_all()?;
		Ok(())
	})?;
	Ok(())
}

/// Arguments for the process_invoice command
pub struct ProcessInvoiceArgs {
	pub message: Option<String>,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub method: String,
	pub dest: String,
	pub max_outputs: usize,
	pub input: String,
	pub estimate_selection_strategies: bool,
}

/// Process invoice
pub fn process_invoice(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	args: ProcessInvoiceArgs,
	dark_scheme: bool,
) -> Result<(), Error> {
	let adapter = FileWalletCommAdapter::new();
	let slate = adapter.receive_tx_async(&args.input)?;
	controller::owner_single_use(wallet.clone(), |api| {
		if args.estimate_selection_strategies {
			let strategies = vec!["smallest", "all"]
				.into_iter()
				.map(|strategy| {
					let init_args = InitTxArgs {
						src_acct_name: None,
						amount: slate.amount,
						minimum_confirmations: args.minimum_confirmations,
						max_outputs: args.max_outputs as u32,
						num_change_outputs: 1u32,
						selection_strategy: strategy.to_owned(),
						estimate_only: Some(true),
						..Default::default()
					};
					let slate = api.init_send_tx(init_args).unwrap();
					(strategy, slate.amount, slate.fee)
				})
				.collect();
			display::estimate(slate.amount, strategies, dark_scheme);
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: 0,
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs as u32,
				num_change_outputs: 1u32,
				selection_strategy: args.selection_strategy.clone(),
				message: args.message.clone(),
				send_args: None,
				..Default::default()
			};
			if let Err(e) = api.verify_slate_messages(&slate) {
				error!("Error validating participant messages: {}", e);
				return Err(e);
			}
			let result = api.process_invoice_tx(&slate, init_args);
			let mut slate = match result {
				Ok(s) => {
					info!(
						"Invoice processed: {} grin to {} (strategy '{}')",
						core::amount_to_hr_string(slate.amount, false),
						args.dest,
						args.selection_strategy,
					);
					s
				}
				Err(e) => {
					info!("Tx not created: {}", e);
					return Err(e);
				}
			};
			let adapter = match args.method.as_str() {
				"http" => HTTPWalletCommAdapter::new(),
				"file" => FileWalletCommAdapter::new(),
				"self" => NullWalletCommAdapter::new(),
				_ => NullWalletCommAdapter::new(),
			};
			if adapter.supports_sync() {
				slate = adapter.send_tx_sync(&args.dest, &slate)?.0;
				api.tx_lock_outputs(&slate, 0)?;
				if args.method == "self" {
					controller::foreign_single_use(wallet, |api| {
						slate = api.finalize_invoice_tx(&slate)?;
						Ok(())
					})?;
				}
			} else {
				adapter.send_tx_async(&args.dest, &slate)?;
				api.tx_lock_outputs(&slate, 0)?;
			}
		}
		Ok(())
	})?;
	Ok(())
}
/// Info command args
pub struct InfoArgs {
	pub minimum_confirmations: u64,
}

pub fn info(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	g_args: &GlobalArgs,
	args: InfoArgs,
	dark_scheme: bool,
) -> Result<(), Error> {
	controller::owner_single_use(wallet.clone(), |api| {
		let (validated, wallet_info) =
			api.retrieve_summary_info(true, args.minimum_confirmations)?;
		display::info(&g_args.account, &wallet_info, validated, dark_scheme);
		Ok(())
	})?;
	Ok(())
}

/// Outputs command args
pub struct OutputsArgs {
	pub minvalue: Option<u64>,
	pub status: Option<OutputStatus>,
	pub limit: Option<u64>,
}

pub fn outputs(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	g_args: &GlobalArgs,
	args: OutputsArgs,
	dark_scheme: bool,
) -> Result<(), Error> {
	controller::owner_single_use(wallet.clone(), |api| {
		let res = api.node_height()?;
		let (validated, outputs) = api.retrieve_outputs(g_args.show_spent, true, None)?;

		// filter by value
		let mut filtered_outputs = if let Some(minvalue) = args.minvalue {
			outputs
				.into_iter()
				.filter(|out| out.output.value >= minvalue)
				.collect::<Vec<_>>()
		} else {
			outputs
		};

		// filter by status
		if let Some(status) = args.status {
			filtered_outputs = filtered_outputs
				.into_iter()
				.filter(|out| out.output.status == status)
				.collect::<Vec<_>>();
		}

		// limit the display lines
		if let Some(limit) = args.limit {
			if (limit as usize) < filtered_outputs.len() {
				let drop = filtered_outputs.len() - limit as usize;
				filtered_outputs = filtered_outputs.drain(drop..).collect();
			}
		}

		display::outputs(
			&g_args.account,
			res.height,
			validated,
			filtered_outputs,
			dark_scheme,
		)?;
		Ok(())
	})?;
	Ok(())
}

/// Payments command args
pub struct PaymentsArgs {
	pub status: Option<OutputStatus>,
	pub limit: Option<u64>,
}

pub fn payments(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	g_args: &GlobalArgs,
	args: PaymentsArgs,
	dark_scheme: bool,
) -> Result<(), Error> {
	controller::owner_single_use(wallet.clone(), |api| {
		let res = api.node_height()?;
		let (validated, outputs) = api.retrieve_payments(true, None)?;

		// filter by status
		let mut filtered_outputs = if let Some(status) = args.status {
			outputs
				.into_iter()
				.filter(|out| out.status == status)
				.collect::<Vec<_>>()
		} else {
			outputs
		};

		// limit the display lines
		if let Some(limit) = args.limit {
			if (limit as usize) < filtered_outputs.len() {
				let drop = filtered_outputs.len() - limit as usize;
				filtered_outputs = filtered_outputs.drain(drop..).collect();
			}
		}

		display::payments(
			&g_args.account,
			res.height,
			validated,
			filtered_outputs,
			dark_scheme,
		)?;
		Ok(())
	})?;
	Ok(())
}

/// Txs command args
pub struct TxsArgs {
	pub id: Option<u32>,
	pub show_raw_tx_data: bool,
	pub tx_type: Option<TxLogEntryType>,
	pub start_date: Option<DateTime>,
	pub end_date: Option<DateTime>,
	pub limit: Option<u64>,
}

pub fn txs(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	g_args: &GlobalArgs,
	args: TxsArgs,
	dark_scheme: bool,
) -> Result<(), Error> {
	controller::owner_single_use(wallet.clone(), |api| {
		let res = api.node_height()?;
		let (validated, txs) = api.retrieve_txs(true, args.id, None)?;
		let include_status = !args.id.is_some();

		let mut filtered_txs;
		{
			// Filter by tx type
			filtered_txs = if let Some(tx_type) = args.tx_type {
				txs.into_iter()
					.filter(|tx| tx.tx_type == tx_type)
					.collect::<Vec<_>>()
			} else {
				txs
			};

			// Filter by date
			if let Some(start_date) = args.start_date {
				if let Some(end_date) = args.end_date {
					filtered_txs = filtered_txs
						.into_iter()
						.filter(|tx| {
							tx.creation_ts.naive_local() >= start_date
								&& tx.creation_ts.naive_local() <= end_date
						})
						.collect::<Vec<_>>();
				}
			}

			// limit the display lines
			if let Some(limit) = args.limit {
				if (limit as usize) < filtered_txs.len() {
					let drop = filtered_txs.len() - limit as usize;
					filtered_txs = filtered_txs.drain(drop..).collect();
				}
			}
		}

		display::txs(
			&g_args.account,
			res.height,
			validated,
			&filtered_txs,
			include_status,
			dark_scheme,
		)?;
		// if given a particular transaction id, also get and display associated
		// inputs/outputs and messages
		if args.id.is_some() {
			let (_, outputs) = api.retrieve_outputs(true, false, args.id)?;
			display::outputs(&g_args.account, res.height, validated, outputs, dark_scheme)?;
			// should only be one here, but just in case
			for tx in &filtered_txs {
				let (_, outputs) = api.retrieve_payments(true, tx.tx_slate_id)?;
				if outputs.len() > 0 {
					display::payments(
						&g_args.account,
						res.height,
						validated,
						outputs,
						dark_scheme,
					)?;
				}
			}

			// should only be one here, but just in case
			for tx in &filtered_txs {
				display::tx_messages(tx, dark_scheme)?;
			}

			if args.show_raw_tx_data {
				if filtered_txs.len() == 1 && filtered_txs[0].stored_tx.is_some() {
					if let Some(stored_tx) = api.get_stored_tx(&filtered_txs[0])? {
						println!();
						println!("{}", "The raw transaction data:".magenta());
						println!("{}", json::to_string_pretty(&stored_tx).unwrap());
						println!();
					}
				}
			}
		};
		Ok(())
	})?;
	Ok(())
}

/// Proof command args
#[derive(Clone, Debug)]
pub enum ProofArgs<'a> {
	Export(u32, &'a str, &'a str),
	Verify(&'a str),
}

/// Proof
pub fn proof(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	_g_args: &GlobalArgs,
	args: ProofArgs,
	config: &WalletConfig,
	dark_scheme: bool,
) -> Result<(), Error> {
	let home_dir = dirs::home_dir()
		.map(|p| p.to_str().unwrap().to_string())
		.unwrap_or("~".to_string());

	controller::owner_single_use(wallet.clone(), |api| {
		match args {
			ProofArgs::Export(index, filename, msg) => {
				let tx_proof = api.get_stored_tx_proof(Some(index), None)?;
				if let Some(mut tx_proof) = tx_proof {
					let verified = api.verify_tx_proof(
						&tx_proof,
						&config.check_node_api_http_addr,
						config.node_api_secret.clone(),
					)?;
					if !msg.is_empty() {
						tx_proof.prover_msg = Some(msg.to_string());
						let tx_entries = api.retrieve_txs(false, Some(index), None)?.1;
						if tx_entries.len() > 0 {
							if let Some(grinrelay_key_path) =
								tx_entries.first().unwrap().grinrelay_key_path
							{
								let _ = api.sign_tx_proof(grinrelay_key_path, &mut tx_proof)?;
							}
						}
					}

					let mut file = File::create(filename.replace("~", &home_dir))?;
					file.write_all(serde_json::to_string(&tx_proof)?.as_bytes())?;
					println!("Proof exported to {}", filename.bright_green());
					let _ = display::proof(verified, dark_scheme);
				} else {
					println!("No proof for this transaction");
				}
			}
			ProofArgs::Verify(filename) => {
				let mut file = File::open(filename.replace("~", &home_dir))?;
				let mut tx_proof = String::new();
				file.read_to_string(&mut tx_proof)?;
				let tx_proof: TxProof = serde_json::from_str(&tx_proof)?;
				let verified = api.verify_tx_proof(
					&tx_proof,
					&config.check_node_api_http_addr,
					config.node_api_secret.clone(),
				)?;
				let _ = display::proof(verified, dark_scheme);
			}
		};
		Ok(())
	})?;
	Ok(())
}

/// Address
pub fn address(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	grinrelay_config: GrinRelayConfig,
) -> Result<(), Error> {
	let relay_addr = controller::grinrelay_address(wallet, grinrelay_config)?;
	println!(
		"Your current Grin Relay address for receiving: {}\
		 \n(Please run `grin-wallet listen` for receiving Grin on this address.)",
		relay_addr.bright_green(),
	);
	Ok(())
}

/// Repost
pub struct RepostArgs {
	pub id: u32,
	pub dump_file: Option<String>,
	pub fluff: bool,
}

pub fn repost(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	args: RepostArgs,
) -> Result<(), Error> {
	controller::owner_single_use(wallet.clone(), |api| {
		let (_, txs) = api.retrieve_txs(true, Some(args.id), None)?;
		let stored_tx = api.get_stored_tx(&txs[0])?;
		if stored_tx.is_none() {
			error!(
				"Transaction with id {} does not have transaction data. Not reposting.",
				args.id
			);
			return Ok(());
		}
		match args.dump_file {
			None => {
				if txs[0].confirmed {
					error!(
						"Transaction with id {} is confirmed. Not reposting.",
						args.id
					);
					return Ok(());
				}
				api.post_tx(txs[0].tx_slate_id, &stored_tx.unwrap(), args.fluff)?;
				info!("Reposted transaction at {}", args.id);
				return Ok(());
			}
			Some(f) => {
				let mut tx_file = File::create(f.clone())?;
				tx_file.write_all(json::to_string(&stored_tx).unwrap().as_bytes())?;
				tx_file.sync_all()?;
				info!("Dumped transaction data for tx {} to {}", args.id, f);
				return Ok(());
			}
		}
	})?;
	Ok(())
}

/// Cancel
pub struct CancelArgs {
	pub tx_id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
	pub tx_id_string: String,
}

pub fn cancel(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	args: CancelArgs,
) -> Result<(), Error> {
	controller::owner_single_use(wallet.clone(), |api| {
		let result = api.cancel_tx(args.tx_id, args.tx_slate_id);
		match result {
			Ok(_) => {
				info!("Transaction {} Cancelled", args.tx_id_string);
				Ok(())
			}
			Err(e) => {
				error!("TX Cancellation failed: {}", e);
				Err(e)
			}
		}
	})?;
	Ok(())
}

pub fn restore(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
) -> Result<(), Error> {
	controller::owner_single_use(wallet.clone(), |api| {
		let result = api.restore();
		match result {
			Ok(_) => {
				info!("Wallet restore complete",);
				Ok(())
			}
			Err(e) => {
				error!("Wallet restore failed: {}", e);
				error!("Backtrace: {}", e.backtrace().unwrap());
				Err(e)
			}
		}
	})?;
	Ok(())
}

/// wallet check
pub struct CheckArgs {
	pub delete_unconfirmed: bool,
}

pub fn check_repair(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	args: CheckArgs,
) -> Result<(), Error> {
	controller::owner_single_use(wallet.clone(), |api| {
		info!("Starting wallet check...",);
		info!("Updating all wallet outputs, please wait ...",);
		let result = api.check_repair(args.delete_unconfirmed);
		match result {
			Ok(_) => {
				info!("Wallet check complete",);
				Ok(())
			}
			Err(e) => {
				error!("Wallet check failed: {}", e);
				error!("Backtrace: {}", e.backtrace().unwrap());
				Err(e)
			}
		}
	})?;
	Ok(())
}

/// wallet check
pub struct PwdUpdateArgs {
	pub new_password: ZeroingString,
}

pub fn change_password(
	wallet: Arc<Mutex<WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>,
	g_args: &GlobalArgs,
	args: PwdUpdateArgs,
) -> Result<(), Error> {
	controller::owner_single_use(wallet.clone(), |api| {
		let result = api.change_password(&g_args.password, &args.new_password);
		match result {
			Ok(_) => {
				warn!("Your password has been changed successfully!",);
				Ok(())
			}
			Err(e) => {
				error!("Password change failed: {}", e);
				Err(e)
			}
		}
	})?;
	Ok(())
}
