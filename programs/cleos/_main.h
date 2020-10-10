#include <pwd.h>
#include <string>
#include <vector>
#include <regex>
#include <iostream>
#include <fc/crypto/hex.hpp>
#include <fc/variant.hpp>
#include <fc/io/datastream.hpp>
#include <fc/io/json.hpp>
#include <fc/io/console.hpp>
#include <fc/exception/exception.hpp>
#include <fc/variant_object.hpp>
#include <fc/static_variant.hpp>

#include <eosio/chain/name.hpp>
#include <eosio/chain/config.hpp>
#include <eosio/chain/wast_to_wasm.hpp>
#include <eosio/chain/trace.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/chain/contract_types.hpp>

#include <eosio/version/version.hpp>

#pragma push_macro("N")
#undef N

#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <boost/process/spawn.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <boost/range/algorithm/sort.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/algorithm/string/classification.hpp>

#pragma pop_macro("N")

#include <Inline/BasicTypes.h>
#include <IR/Module.h>
#include <IR/Validate.h>
#include <WASM/WASM.h>
#include <Runtime/Runtime.h>

#include <fc/io/fstream.hpp>

#define CLI11_HAS_FILESYSTEM 0
#include "CLI11.hpp"
#include "help_text.hpp"
#include "localize.hpp"
#include "config.hpp"
#include "httpc.hpp"

using namespace std;
using namespace eosio;
using namespace eosio::chain;
using namespace eosio::client::help;
using namespace eosio::client::http;
using namespace eosio::client::localize;
using namespace eosio::client::config;
using namespace boost::filesystem;
using auth_type = fc::static_variant<public_key_type, permission_level>;

FC_DECLARE_EXCEPTION( explained_exception, 9000000, "explained exception, see error log" );
FC_DECLARE_EXCEPTION( localized_exception, 10000000, "an error occured" );
#define EOSC_ASSERT( TEST, ... ) \
  FC_EXPAND_MACRO( \
    FC_MULTILINE_MACRO_BEGIN \
      if( UNLIKELY(!(TEST)) ) \
      {                                                   \
        std::cerr << localized( __VA_ARGS__ ) << std::endl;  \
        FC_THROW_EXCEPTION( explained_exception, #TEST ); \
      }                                                   \
    FC_MULTILINE_MACRO_END \
  )

//copy pasta from keosd's main.cpp
bfs::path determine_home_directory();
std::string clean_output( std::string str );
void add_standard_transaction_options(CLI::App* cmd, string default_permission = "");
vector<chain::permission_level> get_account_permissions(const vector<string>& permissions); 
vector<chain::permission_level> get_account_permissions(const vector<string>& permissions, const chain::permission_level& default_permission); 

template<typename T>
fc::variant call( const std::string& url,
                  const std::string& path,
                  const T& v ); 

template<typename T>
fc::variant call( const std::string& path,
                  const T& v ); 

template<>
fc::variant call( const std::string& url,
                  const std::string& path);

eosio::chain_apis::read_only::get_info_results get_info(); 
string generate_nonce_string();
chain::action generate_nonce_action(); 
void prompt_for_wallet_password(string& pw, const string& name); 
fc::variant determine_required_keys(const signed_transaction& trx); 


void sign_transaction(signed_transaction& trx, fc::variant& required_keys, const chain_id_type& chain_id); 


fc::variant push_transaction( signed_transaction& trx, packed_transaction::compression_type compression = packed_transaction::compression_type::none ); 


fc::variant push_actions(std::vector<chain::action>&& actions, packed_transaction::compression_type compression = packed_transaction::compression_type::none ); 

void print_action( const fc::variant& at ); 

//resolver for ABI serializer to decode actions in proposed transaction in multisig contract
auto abi_serializer_resolver = [](const name& account) -> fc::optional<abi_serializer>;

bytes variant_to_bin( const account_name& account, const action_name& action, const fc::variant& action_args_var ); 

fc::variant bin_to_variant( const account_name& account, const action_name& action, const bytes& action_args); 

fc::variant json_from_file_or_string(const string& file_or_str, fc::json::parse_type ptype = fc::json::parse_type::legacy_parser);

bytes json_or_file_to_bin( const account_name& account, const action_name& action, const string& data_or_filename ); 

void print_action_tree( const fc::variant& action ); 

void print_result( const fc::variant& result );

void send_actions(std::vector<chain::action>&& actions, packed_transaction::compression_type compression = packed_transaction::compression_type::none );

void send_transaction( signed_transaction& trx, packed_transaction::compression_type compression = packed_transaction::compression_type::none  ); 

chain::permission_level to_permission_level(const std::string& s);

chain::action create_newaccount(const name& creator, const name& newaccount, auth_type owner, auth_type active);

chain::action create_action(const vector<permission_level>& authorization, const account_name& code, const action_name& act, const fc::variant& args);

chain::action create_buyram(const name& creator, const name& newaccount, const asset& quantity);

chain::action create_buyrambytes(const name& creator, const name& newaccount, uint32_t numbytes);

chain::action create_delegate(const name& from, const name& receiver, const asset& net, const asset& cpu, bool transfer);

fc::variant regproducer_variant(const account_name& producer, const public_key_type& key, const string& url, uint16_t location);

chain::action create_open(const string& contract, const name& owner, symbol sym, const name& ram_payer);
chain::action create_transfer(const string& contract, const name& sender, const name& recipient, asset amount, const string& memo );

chain::action create_setabi(const name& account, const bytes& abi);

chain::action create_setcode(const name& account, const bytes& code);

chain::action create_updateauth(const name& account, const name& permission, const name& parent, const authority& auth);

chain::action create_deleteauth(const name& account, const name& permission);

chain::action create_linkauth(const name& account, const name& code, const name& type, const name& requirement);

chain::action create_unlinkauth(const name& account, const name& code, const name& type);

authority parse_json_authority(const std::string& authorityJsonOrFile);

authority parse_json_authority_or_key(const std::string& authorityJsonOrFile);

asset to_asset( account_name code, const string& s );

inline asset to_asset( const string& s );

struct set_account_permission_subcommand {
   string account;
   string permission;
   string authority_json_or_file;
   string parent;
   bool add_code = false;
   bool remove_code = false;

   set_account_permission_subcommand(CLI::App* accountCmd) {
      auto permissions = accountCmd->add_subcommand("permission", localized("set parameters dealing with account permissions"));
      permissions->add_option("account", account, localized("The account to set/delete a permission authority for"))->required();
      permissions->add_option("permission", permission, localized("The permission name to set/delete an authority for"))->required();
      permissions->add_option("authority", authority_json_or_file, localized("[delete] NULL, [create/update] public key, JSON string or filename defining the authority, [code] contract name"));
      permissions->add_option("parent", parent, localized("[create] The permission name of this parents permission, defaults to 'active'"));
      permissions->add_flag("--add-code", add_code, localized("[code] add '${code}' permission to specified permission authority", ("code", name(config::eosio_code_name))));
      permissions->add_flag("--remove-code", remove_code, localized("[code] remove '${code}' permission from specified permission authority", ("code", name(config::eosio_code_name))));

      add_standard_transaction_options(permissions, "account@active");

      permissions->callback([this] {
         EOSC_ASSERT( !(add_code && remove_code), "ERROR: Either --add-code or --remove-code can be set" );
         EOSC_ASSERT( (add_code ^ remove_code) || !authority_json_or_file.empty(), "ERROR: authority should be specified unless add or remove code permission" );

         authority auth;

         bool need_parent = parent.empty() && (name(permission) != name("owner"));
         bool need_auth = add_code || remove_code;

         if ( !need_auth && boost::iequals(authority_json_or_file, "null") ) {
            send_actions( { create_deleteauth(name(account), name(permission)) } );
            return;
         }

         if ( need_parent || need_auth ) {
            fc::variant json = call(get_account_func, fc::mutable_variant_object("account_name", account));
            auto res = json.as<eosio::chain_apis::read_only::get_account_results>();
            auto itr = std::find_if(res.permissions.begin(), res.permissions.end(), [&](const auto& perm) {
               return perm.perm_name == name(permission);
            });

            if ( need_parent ) {
               // see if we can auto-determine the proper parent
               if ( itr != res.permissions.end() ) {
                  parent = (*itr).parent.to_string();
               } else {
                  // if this is a new permission and there is no parent we default to "active"
                  parent = config::active_name.to_string();
               }
            }

            if ( need_auth ) {
               auto actor = (authority_json_or_file.empty()) ? name(account) : name(authority_json_or_file);
               auto code_name = config::eosio_code_name;

               if ( itr != res.permissions.end() ) {
                  // fetch existing authority
                  auth = std::move((*itr).required_auth);

                  auto code_perm = permission_level { actor, code_name };
                  auto itr2 = std::lower_bound(auth.accounts.begin(), auth.accounts.end(), code_perm, [&](const auto& perm_level, const auto& value) {
                     return perm_level.permission < value; // Safe since valid authorities must order the permissions in accounts in ascending order
                  });

                  if ( add_code ) {
                     if ( itr2 != auth.accounts.end() && itr2->permission == code_perm ) {
                        // authority already contains code permission, promote its weight to satisfy threshold
                        if ( (*itr2).weight < auth.threshold ) {
                           if ( auth.threshold > std::numeric_limits<weight_type>::max() ) {
                              std::cerr << "ERROR: Threshold is too high to be satisfied by sole code permission" << std::endl;
                              return;
                           }
                           std::cerr << localized("The weight of '${actor}@${code}' in '${permission}' permission authority will be increased up to threshold",
                                                  ("actor", actor)("code", code_name)("permission", permission)) << std::endl;
                           (*itr2).weight = static_cast<weight_type>(auth.threshold);
                        } else {
                           std::cerr << localized("ERROR: The permission '${permission}' already contains '${actor}@${code}'",
                                                  ("permission", permission)("actor", actor)("code", code_name)) << std::endl;
                           return ;
                        }
                     } else {
                        // add code permission to specified authority
                        if ( auth.threshold > std::numeric_limits<weight_type>::max() ) {
                           std::cerr << "ERROR: Threshold is too high to be satisfied by sole code permission" << std::endl;
                           return;
                        }
                        auth.accounts.insert( itr2, permission_level_weight {
                           .permission = { actor, code_name },
                           .weight = static_cast<weight_type>(auth.threshold)
                        });
                     }
                  } else {
                     if ( itr2 != auth.accounts.end() && itr2->permission == code_perm ) {
                        // remove code permission, if authority becomes empty by the removal of code permission, delete permission
                        auth.accounts.erase( itr2 );
                        if ( auth.keys.empty() && auth.accounts.empty() && auth.waits.empty() ) {
                           send_actions( { create_deleteauth(name(account), name(permission)) } );
                           return;
                        }
                     } else {
                        // authority doesn't contain code permission
                        std::cerr << localized("ERROR: '${actor}@${code}' does not exist in '${permission}' permission authority",
                                               ("actor", actor)("code", code_name)("permission", permission)) << std::endl;
                        return;
                     }
                  }
               } else {
                  if ( add_code ) {
                     // create new permission including code permission
                     auth.threshold = 1;
                     auth.accounts.push_back( permission_level_weight {
                        .permission = { actor, code_name },
                        .weight = 1
                     });
                  } else {
                     // specified permission doesn't exist, so failed to remove code permission from it
                     std::cerr << localized("ERROR: The permission '${permission}' does not exist", ("permission", permission)) << std::endl;
                     return;
                  }
               }
            }
         }

         if ( !need_auth ) {
            auth = parse_json_authority_or_key(authority_json_or_file);
         }

         send_actions( { create_updateauth(name(account), name(permission), name(parent), auth) } );
      });
   }
};

struct set_action_permission_subcommand {
   string accountStr;
   string codeStr;
   string typeStr;
   string requirementStr;

   set_action_permission_subcommand(CLI::App* actionRoot) {
      auto permissions = actionRoot->add_subcommand("permission", localized("set parmaters dealing with account permissions"));
      permissions->add_option("account", accountStr, localized("The account to set/delete a permission authority for"))->required();
      permissions->add_option("code", codeStr, localized("The account that owns the code for the action"))->required();
      permissions->add_option("type", typeStr, localized("the type of the action"))->required();
      permissions->add_option("requirement", requirementStr, localized("[delete] NULL, [set/update] The permission name require for executing the given action"))->required();

      add_standard_transaction_options(permissions, "account@active");

      permissions->callback([this] {
         name account = name(accountStr);
         name code = name(codeStr);
         name type = name(typeStr);
         bool is_delete = boost::iequals(requirementStr, "null");

         if (is_delete) {
            send_actions({create_unlinkauth(account, code, type)});
         } else {
            name requirement = name(requirementStr);
            send_actions({create_linkauth(account, code, type, requirement)});
         }
      });
   }
};


bool local_port_used() {
    using namespace boost::asio;

    io_service ios;
    local::stream_protocol::endpoint endpoint(wallet_url.substr(strlen("unix://")));
    local::stream_protocol::socket socket(ios);
    boost::system::error_code ec;
    socket.connect(endpoint, ec);

    return !ec;
}

void try_local_port(uint32_t duration) {
   using namespace std::chrono;
   auto start_time = duration_cast<std::chrono::milliseconds>( system_clock::now().time_since_epoch() ).count();
   while ( !local_port_used()) {
      if (duration_cast<std::chrono::milliseconds>( system_clock::now().time_since_epoch()).count() - start_time > duration ) {
         std::cerr << "Unable to connect to " << key_store_executable_name << ", if " << key_store_executable_name << " is running please kill the process and try again.\n";
         throw connection_exception(fc::log_messages{FC_LOG_MESSAGE(error, "Unable to connect to ${k}", ("k", key_store_executable_name))});
      }
   }
}

void ensure_keosd_running(CLI::App* app) {
    if (no_auto_keosd)
        return;
    // get, version, net, convert do not require keosd
    if (tx_skip_sign || app->got_subcommand("get") || app->got_subcommand("version") || app->got_subcommand("net") || app->got_subcommand("convert"))
        return;
    if (app->get_subcommand("create")->got_subcommand("key")) // create key does not require wallet
       return;
    if (app->get_subcommand("multisig")->got_subcommand("review")) // multisig review does not require wallet
       return;
    if (auto* subapp = app->get_subcommand("system")) {
       if (subapp->got_subcommand("listproducers") || subapp->got_subcommand("listbw") || subapp->got_subcommand("bidnameinfo")) // system list* do not require wallet
         return;
    }
    if (wallet_url != default_wallet_url)
      return;

    if (local_port_used())
       return;

    boost::filesystem::path binPath = boost::dll::program_location();
    binPath.remove_filename();
    // This extra check is necessary when running cleos like this: ./cleos ...
    if (binPath.filename_is_dot())
        binPath.remove_filename();
    binPath.append(key_store_executable_name); // if cleos and keosd are in the same installation directory
    if (!boost::filesystem::exists(binPath)) {
        binPath.remove_filename().remove_filename().append("keosd").append(key_store_executable_name);
    }

    if (boost::filesystem::exists(binPath)) {
        namespace bp = boost::process;
        binPath = boost::filesystem::canonical(binPath);

        vector<std::string> pargs;
        pargs.push_back("--http-server-address");
        pargs.push_back("");
        pargs.push_back("--https-server-address");
        pargs.push_back("");
        pargs.push_back("--unix-socket-path");
        pargs.push_back(string(key_store_executable_name) + ".sock");

        ::boost::process::child keos(binPath, pargs,
                                     bp::std_in.close(),
                                     bp::std_out > bp::null,
                                     bp::std_err > bp::null);
        if (keos.running()) {
            std::cerr << binPath << " launched" << std::endl;
            keos.detach();
            try_local_port(2000);
        } else {
            std::cerr << "No wallet service listening on " << wallet_url << ". Failed to launch " << binPath << std::endl;
        }
    } else {
        std::cerr << "No wallet service listening on "
                  << ". Cannot automatically start " << key_store_executable_name << " because " << key_store_executable_name << " was not found." << std::endl;
    }
}


CLI::callback_t obsoleted_option_host_port = [](CLI::results_t) {
   std::cerr << localized("Host and port options (-H, --wallet-host, etc.) have been replaced with -u/--url and --wallet-url\n"
                          "Use for example -u http://localhost:8888 or --url https://example.invalid/\n");
   exit(1);
   return false;
};

struct register_producer_subcommand {
   string producer_str;
   string producer_key_str;
   string url;
   uint16_t loc = 0;

   register_producer_subcommand(CLI::App* actionRoot) {
      auto register_producer = actionRoot->add_subcommand("regproducer", localized("Register a new producer"));
      register_producer->add_option("account", producer_str, localized("The account to register as a producer"))->required();
      register_producer->add_option("producer_key", producer_key_str, localized("The producer's public key"))->required();
      register_producer->add_option("url", url, localized("url where info about producer can be found"), true);
      register_producer->add_option("location", loc, localized("relative location for purpose of nearest neighbor scheduling"), true);
      add_standard_transaction_options(register_producer, "account@active");


      register_producer->callback([this] {
         public_key_type producer_key;
         try {
            producer_key = public_key_type(producer_key_str);
         } EOS_RETHROW_EXCEPTIONS(public_key_type_exception, "Invalid producer public key: ${public_key}", ("public_key", producer_key_str))

         auto regprod_var = regproducer_variant(name(producer_str), producer_key, url, loc );
         auto accountPermissions = get_account_permissions(tx_permission, {name(producer_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, N(regproducer), regprod_var)});
      });
   }
};

struct create_account_subcommand {
   string creator;
   string account_name;
   string owner_key_str;
   string active_key_str;
   string stake_net;
   string stake_cpu;
   uint32_t buy_ram_bytes_in_kbytes = 0;
   uint32_t buy_ram_bytes = 0;
   string buy_ram_eos;
   bool transfer = false;
   bool simple = false;

   create_account_subcommand(CLI::App* actionRoot, bool s) : simple(s) {
      auto createAccount = actionRoot->add_subcommand(
                              (simple ? "account" : "newaccount"),
                              (simple ? localized("Create a new account on the blockchain (assumes system contract does not restrict RAM usage)")
                                      : localized("Create a new account on the blockchain with initial resources") )
      );
      createAccount->add_option("creator", creator, localized("The name of the account creating the new account"))->required();
      createAccount->add_option("name", account_name, localized("The name of the new account"))->required();
      createAccount->add_option("OwnerKey", owner_key_str, localized("The owner public key or permission level for the new account"))->required();
      createAccount->add_option("ActiveKey", active_key_str, localized("The active public key or permission level for the new account"));

      if (!simple) {
         createAccount->add_option("--stake-net", stake_net,
                                   (localized("The amount of tokens delegated for net bandwidth")))->required();
         createAccount->add_option("--stake-cpu", stake_cpu,
                                   (localized("The amount of tokens delegated for CPU bandwidth")))->required();
         createAccount->add_option("--buy-ram-kbytes", buy_ram_bytes_in_kbytes,
                                   (localized("The amount of RAM bytes to purchase for the new account in kibibytes (KiB)")));
         createAccount->add_option("--buy-ram-bytes", buy_ram_bytes,
                                   (localized("The amount of RAM bytes to purchase for the new account in bytes")));
         createAccount->add_option("--buy-ram", buy_ram_eos,
                                   (localized("The amount of RAM bytes to purchase for the new account in tokens")));
         createAccount->add_flag("--transfer", transfer,
                                 (localized("Transfer voting power and right to unstake tokens to receiver")));
      }

      add_standard_transaction_options(createAccount, "creator@active");

      createAccount->callback([this] {
            auth_type owner, active;

            if( owner_key_str.find('@') != string::npos ) {
               try {
                  owner = to_permission_level(owner_key_str);
               } EOS_RETHROW_EXCEPTIONS( explained_exception, "Invalid owner permission level: ${permission}", ("permission", owner_key_str) )
            } else {
               try {
                  owner = public_key_type(owner_key_str);
               } EOS_RETHROW_EXCEPTIONS( public_key_type_exception, "Invalid owner public key: ${public_key}", ("public_key", owner_key_str) );
            }

            if( active_key_str.empty() ) {
               active = owner;
            } else if( active_key_str.find('@') != string::npos ) {
               try {
                  active = to_permission_level(active_key_str);
               } EOS_RETHROW_EXCEPTIONS( explained_exception, "Invalid active permission level: ${permission}", ("permission", active_key_str) )
            } else {
               try {
                  active = public_key_type(active_key_str);
               } EOS_RETHROW_EXCEPTIONS( public_key_type_exception, "Invalid active public key: ${public_key}", ("public_key", active_key_str) );
            }

            auto create = create_newaccount(name(creator), name(account_name), owner, active);
            if (!simple) {
               EOSC_ASSERT( buy_ram_eos.size() || buy_ram_bytes_in_kbytes || buy_ram_bytes, "ERROR: One of --buy-ram, --buy-ram-kbytes or --buy-ram-bytes should have non-zero value" );
               EOSC_ASSERT( !buy_ram_bytes_in_kbytes || !buy_ram_bytes, "ERROR: --buy-ram-kbytes and --buy-ram-bytes cannot be set at the same time" );
               action buyram = !buy_ram_eos.empty() ? create_buyram(name(creator), name(account_name), to_asset(buy_ram_eos))
                  : create_buyrambytes(name(creator), name(account_name), (buy_ram_bytes_in_kbytes) ? (buy_ram_bytes_in_kbytes * 1024) : buy_ram_bytes);
               auto net = to_asset(stake_net);
               auto cpu = to_asset(stake_cpu);
               if ( net.get_amount() != 0 || cpu.get_amount() != 0 ) {
                  action delegate = create_delegate( name(creator), name(account_name), net, cpu, transfer);
                  send_actions( { create, buyram, delegate } );
               } else {
                  send_actions( { create, buyram } );
               }
            } else {
               send_actions( { create } );
            }
      });
   }
};

struct unregister_producer_subcommand {
   string producer_str;

   unregister_producer_subcommand(CLI::App* actionRoot) {
      auto unregister_producer = actionRoot->add_subcommand("unregprod", localized("Unregister an existing producer"));
      unregister_producer->add_option("account", producer_str, localized("The account to unregister as a producer"))->required();
      add_standard_transaction_options(unregister_producer, "account@active");

      unregister_producer->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
                  ("producer", producer_str);

         auto accountPermissions = get_account_permissions(tx_permission, {name(producer_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, N(unregprod), act_payload)});
      });
   }
};

struct vote_producer_proxy_subcommand {
   string voter_str;
   string proxy_str;

   vote_producer_proxy_subcommand(CLI::App* actionRoot) {
      auto vote_proxy = actionRoot->add_subcommand("proxy", localized("Vote your stake through a proxy"));
      vote_proxy->add_option("voter", voter_str, localized("The voting account"))->required();
      vote_proxy->add_option("proxy", proxy_str, localized("The proxy account"))->required();
      add_standard_transaction_options(vote_proxy, "voter@active");

      vote_proxy->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
                  ("voter", voter_str)
                  ("proxy", proxy_str)
                  ("producers", std::vector<account_name>{});
         auto accountPermissions = get_account_permissions(tx_permission, {name(voter_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, N(voteproducer), act_payload)});
      });
   }
};

struct vote_producers_subcommand {
   string voter_str;
   vector<std::string> producer_names;

   vote_producers_subcommand(CLI::App* actionRoot) {
      auto vote_producers = actionRoot->add_subcommand("prods", localized("Vote for one or more producers"));
      vote_producers->add_option("voter", voter_str, localized("The voting account"))->required();
      vote_producers->add_option("producers", producer_names, localized("The account(s) to vote for. All options from this position and following will be treated as the producer list."))->required();
      add_standard_transaction_options(vote_producers, "voter@active");

      vote_producers->callback([this] {

         std::sort( producer_names.begin(), producer_names.end() );

         fc::variant act_payload = fc::mutable_variant_object()
                  ("voter", voter_str)
                  ("proxy", "")
                  ("producers", producer_names);
         auto accountPermissions = get_account_permissions(tx_permission, {name(voter_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, N(voteproducer), act_payload)});
      });
   }
};

struct approve_producer_subcommand {
   string voter;
   string producer_name;

   approve_producer_subcommand(CLI::App* actionRoot) {
      auto approve_producer = actionRoot->add_subcommand("approve", localized("Add one producer to list of voted producers"));
      approve_producer->add_option("voter", voter, localized("The voting account"))->required();
      approve_producer->add_option("producer", producer_name, localized("The account to vote for"))->required();
      add_standard_transaction_options(approve_producer, "voter@active");

      approve_producer->callback([this] {
            auto result = call(get_table_func, fc::mutable_variant_object("json", true)
                               ("code", name(config::system_account_name).to_string())
                               ("scope", name(config::system_account_name).to_string())
                               ("table", "voters")
                               ("table_key", "owner")
                               ("lower_bound", name(voter).to_uint64_t())
                               ("upper_bound", name(voter).to_uint64_t() + 1)
                               // Less than ideal upper_bound usage preserved so cleos can still work with old buggy nodeos versions
                               // Change to voter.value when cleos no longer needs to support nodeos versions older than 1.5.0
                               ("limit", 1)
            );
            auto res = result.as<eosio::chain_apis::read_only::get_table_rows_result>();
            // Condition in if statement below can simply be res.rows.empty() when cleos no longer needs to support nodeos versions older than 1.5.0
            // Although since this subcommand will actually change the voter's vote, it is probably better to just keep this check to protect
            //  against future potential chain_plugin bugs.
            if( res.rows.empty() || res.rows[0].get_object()["owner"].as_string() != name(voter).to_string() ) {
               std::cerr << "Voter info not found for account " << voter << std::endl;
               return;
            }
            EOS_ASSERT( 1 == res.rows.size(), multiple_voter_info, "More than one voter_info for account" );
            auto prod_vars = res.rows[0]["producers"].get_array();
            vector<eosio::name> prods;
            for ( auto& x : prod_vars ) {
               prods.push_back( name(x.as_string()) );
            }
            prods.push_back( name(producer_name) );
            std::sort( prods.begin(), prods.end() );
            auto it = std::unique( prods.begin(), prods.end() );
            if (it != prods.end() ) {
               std::cerr << "Producer \"" << producer_name << "\" is already on the list." << std::endl;
               return;
            }
            fc::variant act_payload = fc::mutable_variant_object()
               ("voter", voter)
               ("proxy", "")
               ("producers", prods);
            auto accountPermissions = get_account_permissions(tx_permission, {name(voter), config::active_name});
            send_actions({create_action(accountPermissions, config::system_account_name, N(voteproducer), act_payload)});
      });
   }
};

struct unapprove_producer_subcommand {
   string voter;
   string producer_name;

   unapprove_producer_subcommand(CLI::App* actionRoot) {
      auto approve_producer = actionRoot->add_subcommand("unapprove", localized("Remove one producer from list of voted producers"));
      approve_producer->add_option("voter", voter, localized("The voting account"))->required();
      approve_producer->add_option("producer", producer_name, localized("The account to remove from voted producers"))->required();
      add_standard_transaction_options(approve_producer, "voter@active");

      approve_producer->callback([this] {
            auto result = call(get_table_func, fc::mutable_variant_object("json", true)
                               ("code", name(config::system_account_name).to_string())
                               ("scope", name(config::system_account_name).to_string())
                               ("table", "voters")
                               ("table_key", "owner")
                               ("lower_bound", name(voter).to_uint64_t())
                               ("upper_bound", name(voter).to_uint64_t() + 1)
                               // Less than ideal upper_bound usage preserved so cleos can still work with old buggy nodeos versions
                               // Change to voter.value when cleos no longer needs to support nodeos versions older than 1.5.0
                               ("limit", 1)
            );
            auto res = result.as<eosio::chain_apis::read_only::get_table_rows_result>();
            // Condition in if statement below can simply be res.rows.empty() when cleos no longer needs to support nodeos versions older than 1.5.0
            // Although since this subcommand will actually change the voter's vote, it is probably better to just keep this check to protect
            //  against future potential chain_plugin bugs.
            if( res.rows.empty() || res.rows[0].get_object()["owner"].as_string() != name(voter).to_string() ) {
               std::cerr << "Voter info not found for account " << voter << std::endl;
               return;
            }
            EOS_ASSERT( 1 == res.rows.size(), multiple_voter_info, "More than one voter_info for account" );
            auto prod_vars = res.rows[0]["producers"].get_array();
            vector<eosio::name> prods;
            for ( auto& x : prod_vars ) {
               prods.push_back( name(x.as_string()) );
            }
            auto it = std::remove( prods.begin(), prods.end(), name(producer_name) );
            if (it == prods.end() ) {
               std::cerr << "Cannot remove: producer \"" << producer_name << "\" is not on the list." << std::endl;
               return;
            }
            prods.erase( it, prods.end() ); //should always delete only one element
            fc::variant act_payload = fc::mutable_variant_object()
               ("voter", voter)
               ("proxy", "")
               ("producers", prods);
            auto accountPermissions = get_account_permissions(tx_permission, {name(voter), config::active_name});
            send_actions({create_action(accountPermissions, config::system_account_name, N(voteproducer), act_payload)});
      });
   }
};

struct list_producers_subcommand {
   bool print_json = false;
   uint32_t limit = 50;
   std::string lower;

   list_producers_subcommand(CLI::App* actionRoot) {
      auto list_producers = actionRoot->add_subcommand("listproducers", localized("List producers"));
      list_producers->add_flag("--json,-j", print_json, localized("Output in JSON format"));
      list_producers->add_option("-l,--limit", limit, localized("The maximum number of rows to return"));
      list_producers->add_option("-L,--lower", lower, localized("lower bound value of key, defaults to first"));
      list_producers->callback([this] {
         auto rawResult = call(get_producers_func, fc::mutable_variant_object
            ("json", true)("lower_bound", lower)("limit", limit));
         if ( print_json ) {
            std::cout << fc::json::to_pretty_string(rawResult) << std::endl;
            return;
         }
         auto result = rawResult.as<eosio::chain_apis::read_only::get_producers_result>();
         if ( result.rows.empty() ) {
            std::cout << "No producers found" << std::endl;
            return;
         }
         auto weight = result.total_producer_vote_weight;
         if ( !weight )
            weight = 1;
         printf("%-13s %-57s %-59s %s\n", "Producer", "Producer key", "Url", "Scaled votes");
         for ( auto& row : result.rows )
            printf("%-13.13s %-57.57s %-59.59s %1.4f\n",
                   row["owner"].as_string().c_str(),
                   row["producer_key"].as_string().c_str(),
                   clean_output( row["url"].as_string() ).c_str(),
                   row["total_votes"].as_double() / weight);
         if ( !result.more.empty() )
            std::cout << "-L " << clean_output( result.more ) << " for more" << std::endl;
      });
   }
};

struct get_schedule_subcommand {
   bool print_json = false;

   void print(const char* name, const fc::variant& schedule) {
      if (schedule.is_null()) {
         printf("%s schedule empty\n\n", name);
         return;
      }
      printf("%s schedule version %s\n", name, schedule["version"].as_string().c_str());
      printf("    %-13s %s\n", "Producer", "Producer Authority");
      printf("    %-13s %s\n", "=============", "==================");
      for( auto& row: schedule["producers"].get_array() ) {
         if( row.get_object().contains("block_signing_key") ) {
            // pre 2.0
            printf( "    %-13s %s\n", row["producer_name"].as_string().c_str(), row["block_signing_key"].as_string().c_str() );
         } else {
            printf( "    %-13s ", row["producer_name"].as_string().c_str() );
            auto a = row["authority"].as<block_signing_authority>();
            static_assert( std::is_same<decltype(a), static_variant<block_signing_authority_v0>>::value,
                           "Updates maybe needed if block_signing_authority changes" );
            block_signing_authority_v0 auth = a.get<block_signing_authority_v0>();
            printf( "%s\n", fc::json::to_string( auth, fc::time_point::maximum() ).c_str() );
         }
      }
      printf("\n");
   }

   get_schedule_subcommand(CLI::App* actionRoot) {
      auto get_schedule = actionRoot->add_subcommand("schedule", localized("Retrieve the producer schedule"));
      get_schedule->add_flag("--json,-j", print_json, localized("Output in JSON format"));
      get_schedule->callback([this] {
         auto result = call(get_schedule_func, fc::mutable_variant_object());
         if ( print_json ) {
            std::cout << fc::json::to_pretty_string(result) << std::endl;
            return;
         }
         print("active", result["active"]);
         print("pending", result["pending"]);
         print("proposed", result["proposed"]);
      });
   }
};

struct get_transaction_id_subcommand {
   string trx_to_check;

   get_transaction_id_subcommand(CLI::App* actionRoot) {
      auto get_transaction_id = actionRoot->add_subcommand("transaction_id", localized("Get transaction id given transaction object"));
      get_transaction_id->add_option("transaction", trx_to_check, localized("The JSON string or filename defining the transaction which transaction id we want to retrieve"))->required();

      get_transaction_id->callback([&] {
         try {
            fc::variant trx_var = json_from_file_or_string(trx_to_check);
            if( trx_var.is_object() ) {
               fc::variant_object& vo = trx_var.get_object();
               // if actions.data & actions.hex_data provided, use the hex_data since only currently support unexploded data
               if( vo.contains("actions") ) {
                  if( vo["actions"].is_array() ) {
                     fc::mutable_variant_object mvo = vo;
                     fc::variants& action_variants = mvo["actions"].get_array();
                     for( auto& action_v : action_variants ) {
                        if( !action_v.is_object() ) {
                           std::cerr << "Empty 'action' in transaction" << endl;
                           return;
                        }
                        fc::variant_object& action_vo = action_v.get_object();
                        if( action_vo.contains( "data" ) && action_vo.contains( "hex_data" ) ) {
                           fc::mutable_variant_object maction_vo = action_vo;
                           maction_vo["data"] = maction_vo["hex_data"];
                           action_vo = maction_vo;
                           vo = mvo;
                        } else if( action_vo.contains( "data" ) ) {
                           if( !action_vo["data"].is_string() ) {
                              std::cerr << "get transaction_id only supports un-exploded 'data' (hex form)" << std::endl;
                              return;
                           }
                        }
                     }
                  } else {
                     std::cerr << "transaction json 'actions' is not an array" << std::endl;
                     return;
                  }
               } else {
                  std::cerr << "transaction json does not include 'actions'" << std::endl;
                  return;
               }
               auto trx = trx_var.as<transaction>();
               transaction_id_type id = trx.id();
               if( id == transaction().id() ) {
                  std::cerr << "file/string does not represent a transaction" << std::endl;
               } else {
                  std::cout << string( id ) << std::endl;
               }
            } else {
               std::cerr << "file/string does not represent a transaction" << std::endl;
            }
         } EOS_RETHROW_EXCEPTIONS(transaction_type_exception, "Fail to parse transaction JSON '${data}'", ("data",trx_to_check))
      });
   }
};

struct delegate_bandwidth_subcommand {
   string from_str;
   string receiver_str;
   string stake_net_amount;
   string stake_cpu_amount;
   string stake_storage_amount;
   string buy_ram_amount;
   uint32_t buy_ram_bytes = 0;
   bool transfer = false;

   delegate_bandwidth_subcommand(CLI::App* actionRoot) {
      auto delegate_bandwidth = actionRoot->add_subcommand("delegatebw", localized("Delegate bandwidth"));
      delegate_bandwidth->add_option("from", from_str, localized("The account to delegate bandwidth from"))->required();
      delegate_bandwidth->add_option("receiver", receiver_str, localized("The account to receive the delegated bandwidth"))->required();
      delegate_bandwidth->add_option("stake_net_quantity", stake_net_amount, localized("The amount of tokens to stake for network bandwidth"))->required();
      delegate_bandwidth->add_option("stake_cpu_quantity", stake_cpu_amount, localized("The amount of tokens to stake for CPU bandwidth"))->required();
      delegate_bandwidth->add_option("--buyram", buy_ram_amount, localized("The amount of tokens to buyram"));
      delegate_bandwidth->add_option("--buy-ram-bytes", buy_ram_bytes, localized("The amount of RAM to buy in number of bytes"));
      delegate_bandwidth->add_flag("--transfer", transfer, localized("Transfer voting power and right to unstake tokens to receiver"));
      add_standard_transaction_options(delegate_bandwidth, "from@active");

      delegate_bandwidth->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("receiver", receiver_str)
                  ("stake_net_quantity", to_asset(stake_net_amount))
                  ("stake_cpu_quantity", to_asset(stake_cpu_amount))
                  ("transfer", transfer);
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         std::vector<chain::action> acts{create_action(accountPermissions, config::system_account_name, N(delegatebw), act_payload)};
         EOSC_ASSERT( !(buy_ram_amount.size()) || !buy_ram_bytes, "ERROR: --buyram and --buy-ram-bytes cannot be set at the same time" );
         if (buy_ram_amount.size()) {
            acts.push_back( create_buyram(name(from_str), name(receiver_str), to_asset(buy_ram_amount)) );
         } else if (buy_ram_bytes) {
            acts.push_back( create_buyrambytes(name(from_str), name(receiver_str), buy_ram_bytes) );
         }
         send_actions(std::move(acts));
      });
   }
};

struct undelegate_bandwidth_subcommand {
   string from_str;
   string receiver_str;
   string unstake_net_amount;
   string unstake_cpu_amount;
   uint64_t unstake_storage_bytes;

   undelegate_bandwidth_subcommand(CLI::App* actionRoot) {
      auto undelegate_bandwidth = actionRoot->add_subcommand("undelegatebw", localized("Undelegate bandwidth"));
      undelegate_bandwidth->add_option("from", from_str, localized("The account undelegating bandwidth"))->required();
      undelegate_bandwidth->add_option("receiver", receiver_str, localized("The account to undelegate bandwidth from"))->required();
      undelegate_bandwidth->add_option("unstake_net_quantity", unstake_net_amount, localized("The amount of tokens to undelegate for network bandwidth"))->required();
      undelegate_bandwidth->add_option("unstake_cpu_quantity", unstake_cpu_amount, localized("The amount of tokens to undelegate for CPU bandwidth"))->required();
      add_standard_transaction_options(undelegate_bandwidth, "from@active");

      undelegate_bandwidth->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("receiver", receiver_str)
                  ("unstake_net_quantity", to_asset(unstake_net_amount))
                  ("unstake_cpu_quantity", to_asset(unstake_cpu_amount));
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, N(undelegatebw), act_payload)});
      });
   }
};

struct bidname_subcommand {
   string bidder_str;
   string newname_str;
   string bid_amount;
   bidname_subcommand(CLI::App *actionRoot) {
      auto bidname = actionRoot->add_subcommand("bidname", localized("Name bidding"));
      bidname->add_option("bidder", bidder_str, localized("The bidding account"))->required();
      bidname->add_option("newname", newname_str, localized("The bidding name"))->required();
      bidname->add_option("bid", bid_amount, localized("The amount of tokens to bid"))->required();
      add_standard_transaction_options(bidname, "bidder@active");
      bidname->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
                  ("bidder", bidder_str)
                  ("newname", newname_str)
                  ("bid", to_asset(bid_amount));
         auto accountPermissions = get_account_permissions(tx_permission, {name(bidder_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, N(bidname), act_payload)});
      });
   }
};

struct bidname_info_subcommand {
   bool print_json = false;
   string newname;
   bidname_info_subcommand(CLI::App* actionRoot) {
      auto list_producers = actionRoot->add_subcommand("bidnameinfo", localized("Get bidname info"));
      list_producers->add_flag("--json,-j", print_json, localized("Output in JSON format"));
      list_producers->add_option("newname", newname, localized("The bidding name"))->required();
      list_producers->callback([this] {
         auto rawResult = call(get_table_func, fc::mutable_variant_object("json", true)
                               ("code", "eosio")("scope", "eosio")("table", "namebids")
                               ("lower_bound", name(newname).to_uint64_t())
                               ("upper_bound", name(newname).to_uint64_t() + 1)
                               // Less than ideal upper_bound usage preserved so cleos can still work with old buggy nodeos versions
                               // Change to newname.value when cleos no longer needs to support nodeos versions older than 1.5.0
                               ("limit", 1));
         if ( print_json ) {
            std::cout << fc::json::to_pretty_string(rawResult) << std::endl;
            return;
         }
         auto result = rawResult.as<eosio::chain_apis::read_only::get_table_rows_result>();
         // Condition in if statement below can simply be res.rows.empty() when cleos no longer needs to support nodeos versions older than 1.5.0
         if( result.rows.empty() || result.rows[0].get_object()["newname"].as_string() != name(newname).to_string() ) {
            std::cout << "No bidname record found" << std::endl;
            return;
         }
         const auto& row = result.rows[0];
         string time = row["last_bid_time"].as_string();
         try {
             time = (string)fc::time_point(fc::microseconds(to_uint64(time)));
         } catch (fc::parse_error_exception&) {
         }
         int64_t bid = row["high_bid"].as_int64();
         std::cout << std::left << std::setw(18) << "bidname:" << std::right << std::setw(24) << row["newname"].as_string() << "\n"
                   << std::left << std::setw(18) << "highest bidder:" << std::right << std::setw(24) << row["high_bidder"].as_string() << "\n"
                   << std::left << std::setw(18) << "highest bid:" << std::right << std::setw(24) << (bid > 0 ? bid : -bid) << "\n"
                   << std::left << std::setw(18) << "last bid time:" << std::right << std::setw(24) << time << std::endl;
         if (bid < 0) std::cout << "This auction has already closed" << std::endl;
      });
   }
};

struct list_bw_subcommand {
   string account;
   bool print_json = false;

   list_bw_subcommand(CLI::App* actionRoot) {
      auto list_bw = actionRoot->add_subcommand("listbw", localized("List delegated bandwidth"));
      list_bw->add_option("account", account, localized("The account delegated bandwidth"))->required();
      list_bw->add_flag("--json,-j", print_json, localized("Output in JSON format") );

      list_bw->callback([this] {
            //get entire table in scope of user account
            auto result = call(get_table_func, fc::mutable_variant_object("json", true)
                               ("code", name(config::system_account_name).to_string())
                               ("scope", name(account).to_string())
                               ("table", "delband")
            );
            if (!print_json) {
               auto res = result.as<eosio::chain_apis::read_only::get_table_rows_result>();
               if ( !res.rows.empty() ) {
                  std::cout << std::setw(13) << std::left << "Receiver" << std::setw(21) << std::left << "Net bandwidth"
                            << std::setw(21) << std::left << "CPU bandwidth" << std::endl;
                  for ( auto& r : res.rows ){
                     std::cout << std::setw(13) << std::left << r["to"].as_string()
                               << std::setw(21) << std::left << r["net_weight"].as_string()
                               << std::setw(21) << std::left << r["cpu_weight"].as_string()
                               << std::endl;
                  }
               } else {
                  std::cerr << "Delegated bandwidth not found" << std::endl;
               }
            } else {
               std::cout << fc::json::to_pretty_string(result) << std::endl;
            }
      });
   }
};

struct buyram_subcommand {
   string from_str;
   string receiver_str;
   string amount;
   bool kbytes = false;
   bool bytes = false;

   buyram_subcommand(CLI::App* actionRoot) {
      auto buyram = actionRoot->add_subcommand("buyram", localized("Buy RAM"));
      buyram->add_option("payer", from_str, localized("The account paying for RAM"))->required();
      buyram->add_option("receiver", receiver_str, localized("The account receiving bought RAM"))->required();
      buyram->add_option("amount", amount, localized("The amount of tokens to pay for RAM, or number of bytes/kibibytes of RAM if --bytes/--kbytes is set"))->required();
      buyram->add_flag("--kbytes,-k", kbytes, localized("buyram in number of kibibytes (KiB)"));
      buyram->add_flag("--bytes,-b", bytes, localized("buyram in number of bytes"));
      add_standard_transaction_options(buyram, "payer@active");
      buyram->callback([this] {
         EOSC_ASSERT( !kbytes || !bytes, "ERROR: --kbytes and --bytes cannot be set at the same time" );
         if (kbytes || bytes) {
            send_actions( { create_buyrambytes(name(from_str), name(receiver_str), fc::to_uint64(amount) * ((kbytes) ? 1024ull : 1ull)) } );
         } else {
            send_actions( { create_buyram(name(from_str), name(receiver_str), to_asset(amount)) } );
         }
      });
   }
};

struct sellram_subcommand {
   string from_str;
   string receiver_str;
   uint64_t amount;

   sellram_subcommand(CLI::App* actionRoot) {
      auto sellram = actionRoot->add_subcommand("sellram", localized("Sell RAM"));
      sellram->add_option("account", receiver_str, localized("The account to receive tokens for sold RAM"))->required();
      sellram->add_option("bytes", amount, localized("Number of RAM bytes to sell"))->required();
      add_standard_transaction_options(sellram, "account@active");

      sellram->callback([this] {
            fc::variant act_payload = fc::mutable_variant_object()
               ("account", receiver_str)
               ("bytes", amount);
            auto accountPermissions = get_account_permissions(tx_permission, {name(receiver_str), config::active_name});
            send_actions({create_action(accountPermissions, config::system_account_name, N(sellram), act_payload)});
         });
   }
};

struct claimrewards_subcommand {
   string owner;

   claimrewards_subcommand(CLI::App* actionRoot) {
      auto claim_rewards = actionRoot->add_subcommand("claimrewards", localized("Claim producer rewards"));
      claim_rewards->add_option("owner", owner, localized("The account to claim rewards for"))->required();
      add_standard_transaction_options(claim_rewards, "owner@active");

      claim_rewards->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
                  ("owner", owner);
         auto accountPermissions = get_account_permissions(tx_permission, {name(owner), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, N(claimrewards), act_payload)});
      });
   }
};

struct regproxy_subcommand {
   string proxy;

   regproxy_subcommand(CLI::App* actionRoot) {
      auto register_proxy = actionRoot->add_subcommand("regproxy", localized("Register an account as a proxy (for voting)"));
      register_proxy->add_option("proxy", proxy, localized("The proxy account to register"))->required();
      add_standard_transaction_options(register_proxy, "proxy@active");

      register_proxy->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
                  ("proxy", proxy)
                  ("isproxy", true);
         auto accountPermissions = get_account_permissions(tx_permission, {name(proxy), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, N(regproxy), act_payload)});
      });
   }
};

struct unregproxy_subcommand {
   string proxy;

   unregproxy_subcommand(CLI::App* actionRoot) {
      auto unregister_proxy = actionRoot->add_subcommand("unregproxy", localized("Unregister an account as a proxy (for voting)"));
      unregister_proxy->add_option("proxy", proxy, localized("The proxy account to unregister"))->required();
      add_standard_transaction_options(unregister_proxy, "proxy@active");

      unregister_proxy->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
                  ("proxy", proxy)
                  ("isproxy", false);
         auto accountPermissions = get_account_permissions(tx_permission, {name(proxy), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, N(regproxy), act_payload)});
      });
   }
};

struct canceldelay_subcommand {
   string canceling_account;
   string canceling_permission;
   string trx_id;

   canceldelay_subcommand(CLI::App* actionRoot) {
      auto cancel_delay = actionRoot->add_subcommand("canceldelay", localized("Cancel a delayed transaction"));
      cancel_delay->add_option("canceling_account", canceling_account, localized("Account from authorization on the original delayed transaction"))->required();
      cancel_delay->add_option("canceling_permission", canceling_permission, localized("Permission from authorization on the original delayed transaction"))->required();
      cancel_delay->add_option("trx_id", trx_id, localized("The transaction id of the original delayed transaction"))->required();
      add_standard_transaction_options(cancel_delay, "canceling_account@canceling_permission");

      cancel_delay->callback([this] {
         auto canceling_auth = permission_level{name(canceling_account), name(canceling_permission)};
         fc::variant act_payload = fc::mutable_variant_object()
                  ("canceling_auth", canceling_auth)
                  ("trx_id", trx_id);
         auto accountPermissions = get_account_permissions(tx_permission, canceling_auth);
         send_actions({create_action(accountPermissions, config::system_account_name, N(canceldelay), act_payload)});
      });
   }
};

struct deposit_subcommand {
   string owner_str;
   string amount_str;
   const name act_name{ N(deposit) };

   deposit_subcommand(CLI::App* actionRoot) {
      auto deposit = actionRoot->add_subcommand("deposit", localized("Deposit into owner's REX fund by transfering from owner's liquid token balance"));
      deposit->add_option("owner",  owner_str,  localized("Account which owns the REX fund"))->required();
      deposit->add_option("amount", amount_str, localized("Amount to be deposited into REX fund"))->required();
      add_standard_transaction_options(deposit, "owner@active");
      deposit->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("owner",  owner_str)
            ("amount", amount_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(owner_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct withdraw_subcommand {
   string owner_str;
   string amount_str;
   const name act_name{ N(withdraw) };

   withdraw_subcommand(CLI::App* actionRoot) {
      auto withdraw = actionRoot->add_subcommand("withdraw", localized("Withdraw from owner's REX fund by transfering to owner's liquid token balance"));
      withdraw->add_option("owner",  owner_str,  localized("Account which owns the REX fund"))->required();
      withdraw->add_option("amount", amount_str, localized("Amount to be withdrawn from REX fund"))->required();
      add_standard_transaction_options(withdraw, "owner@active");
      withdraw->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("owner",  owner_str)
            ("amount", amount_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(owner_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct buyrex_subcommand {
   string from_str;
   string amount_str;
   const name act_name{ N(buyrex) };

   buyrex_subcommand(CLI::App* actionRoot) {
      auto buyrex = actionRoot->add_subcommand("buyrex", localized("Buy REX using tokens in owner's REX fund"));
      buyrex->add_option("from",   from_str,   localized("Account buying REX tokens"))->required();
      buyrex->add_option("amount", amount_str, localized("Amount to be taken from REX fund and used in buying REX"))->required();
      add_standard_transaction_options(buyrex, "from@active");
      buyrex->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("from",   from_str)
            ("amount", amount_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct lendrex_subcommand {
   string from_str;
   string amount_str;
   const name act_name1{ N(deposit) };
   const name act_name2{ N(buyrex) };

   lendrex_subcommand(CLI::App* actionRoot) {
      auto lendrex = actionRoot->add_subcommand("lendrex", localized("Deposit tokens to REX fund and use the tokens to buy REX"));
      lendrex->add_option("from",   from_str,   localized("Account buying REX tokens"))->required();
      lendrex->add_option("amount", amount_str, localized("Amount of liquid tokens to be used in buying REX"))->required();
      add_standard_transaction_options(lendrex, "from@active");
      lendrex->callback([this] {
         fc::variant act_payload1 = fc::mutable_variant_object()
            ("owner",  from_str)
            ("amount", amount_str);
         fc::variant act_payload2 = fc::mutable_variant_object()
            ("from",   from_str)
            ("amount", amount_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name1, act_payload1),
                       create_action(accountPermissions, config::system_account_name, act_name2, act_payload2)});
      });
   }
};

struct unstaketorex_subcommand {
   string owner_str;
   string receiver_str;
   string from_net_str;
   string from_cpu_str;
   const name act_name{ N(unstaketorex) };

   unstaketorex_subcommand(CLI::App* actionRoot) {
      auto unstaketorex = actionRoot->add_subcommand("unstaketorex", localized("Buy REX using staked tokens"));
      unstaketorex->add_option("owner",    owner_str,    localized("Account buying REX tokens"))->required();
      unstaketorex->add_option("receiver", receiver_str, localized("Account that tokens have been staked to"))->required();
      unstaketorex->add_option("from_net", from_net_str, localized("Amount to be unstaked from Net resources and used in REX purchase"))->required();
      unstaketorex->add_option("from_cpu", from_cpu_str, localized("Amount to be unstaked from CPU resources and used in REX purchase"))->required();
      add_standard_transaction_options(unstaketorex, "owner@active");
      unstaketorex->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("owner",    owner_str)
            ("receiver", receiver_str)
            ("from_net", from_net_str)
            ("from_cpu", from_cpu_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(owner_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct sellrex_subcommand {
   string from_str;
   string rex_str;
   const name act_name{ N(sellrex) };

   sellrex_subcommand(CLI::App* actionRoot) {
      auto sellrex = actionRoot->add_subcommand("sellrex", localized("Sell REX tokens"));
      sellrex->add_option("from", from_str, localized("Account selling REX tokens"))->required();
      sellrex->add_option("rex",  rex_str,  localized("Amount of REX tokens to be sold"))->required();
      add_standard_transaction_options(sellrex, "from@active");
      sellrex->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("from", from_str)
            ("rex",  rex_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct cancelrexorder_subcommand {
   string owner_str;
   const name act_name{ N(cnclrexorder) };

   cancelrexorder_subcommand(CLI::App* actionRoot) {
      auto cancelrexorder = actionRoot->add_subcommand("cancelrexorder", localized("Cancel queued REX sell order if one exists"));
      cancelrexorder->add_option("owner", owner_str, localized("Owner account of sell order"))->required();
      add_standard_transaction_options(cancelrexorder, "owner@active");
      cancelrexorder->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()("owner", owner_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(owner_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct rentcpu_subcommand {
   string from_str;
   string receiver_str;
   string loan_payment_str;
   string loan_fund_str;
   const name act_name{ N(rentcpu) };

   rentcpu_subcommand(CLI::App* actionRoot) {
      auto rentcpu = actionRoot->add_subcommand("rentcpu", localized("Rent CPU bandwidth for 30 days"));
      rentcpu->add_option("from",         from_str,         localized("Account paying rent fees"))->required();
      rentcpu->add_option("receiver",     receiver_str,     localized("Account to whom rented CPU bandwidth is staked"))->required();
      rentcpu->add_option("loan_payment", loan_payment_str, localized("Loan fee to be paid, used to calculate amount of rented bandwidth"))->required();
      rentcpu->add_option("loan_fund",    loan_fund_str,    localized("Loan fund to be used in automatic renewal, can be 0 tokens"))->required();
      add_standard_transaction_options(rentcpu, "from@active");
      rentcpu->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("from",         from_str)
            ("receiver",     receiver_str)
            ("loan_payment", loan_payment_str)
            ("loan_fund",    loan_fund_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct rentnet_subcommand {
   string from_str;
   string receiver_str;
   string loan_payment_str;
   string loan_fund_str;
   const name act_name{ N(rentnet) };

   rentnet_subcommand(CLI::App* actionRoot) {
      auto rentnet = actionRoot->add_subcommand("rentnet", localized("Rent Network bandwidth for 30 days"));
      rentnet->add_option("from",         from_str,         localized("Account paying rent fees"))->required();
      rentnet->add_option("receiver",     receiver_str,     localized("Account to whom rented Network bandwidth is staked"))->required();
      rentnet->add_option("loan_payment", loan_payment_str, localized("Loan fee to be paid, used to calculate amount of rented bandwidth"))->required();
      rentnet->add_option("loan_fund",    loan_fund_str,    localized("Loan fund to be used in automatic renewal, can be 0 tokens"))->required();
      add_standard_transaction_options(rentnet, "from@active");
      rentnet->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("from",         from_str)
            ("receiver",     receiver_str)
            ("loan_payment", loan_payment_str)
            ("loan_fund",    loan_fund_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct fundcpuloan_subcommand {
   string from_str;
   string loan_num_str;
   string payment_str;
   const name act_name{ N(fundcpuloan) };

   fundcpuloan_subcommand(CLI::App* actionRoot) {
      auto fundcpuloan = actionRoot->add_subcommand("fundcpuloan", localized("Deposit into a CPU loan fund"));
      fundcpuloan->add_option("from",     from_str,     localized("Loan owner"))->required();
      fundcpuloan->add_option("loan_num", loan_num_str, localized("Loan ID"))->required();
      fundcpuloan->add_option("payment",  payment_str,  localized("Amount to be deposited"))->required();
      add_standard_transaction_options(fundcpuloan, "from@active");
      fundcpuloan->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("from",     from_str)
            ("loan_num", loan_num_str)
            ("payment",  payment_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct fundnetloan_subcommand {
   string from_str;
   string loan_num_str;
   string payment_str;
   const name act_name{ N(fundnetloan) };

   fundnetloan_subcommand(CLI::App* actionRoot) {
      auto fundnetloan = actionRoot->add_subcommand("fundnetloan", localized("Deposit into a Network loan fund"));
      fundnetloan->add_option("from",     from_str,     localized("Loan owner"))->required();
      fundnetloan->add_option("loan_num", loan_num_str, localized("Loan ID"))->required();
      fundnetloan->add_option("payment",  payment_str,  localized("Amount to be deposited"))->required();
      add_standard_transaction_options(fundnetloan, "from@active");
      fundnetloan->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("from",     from_str)
            ("loan_num", loan_num_str)
            ("payment",  payment_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct defcpuloan_subcommand {
   string from_str;
   string loan_num_str;
   string amount_str;
   const name act_name{ N(defcpuloan) };

   defcpuloan_subcommand(CLI::App* actionRoot) {
      auto defcpuloan = actionRoot->add_subcommand("defundcpuloan", localized("Withdraw from a CPU loan fund"));
      defcpuloan->add_option("from",     from_str,     localized("Loan owner"))->required();
      defcpuloan->add_option("loan_num", loan_num_str, localized("Loan ID"))->required();
      defcpuloan->add_option("amount",   amount_str,  localized("Amount to be withdrawn"))->required();
      add_standard_transaction_options(defcpuloan, "from@active");
      defcpuloan->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("from",     from_str)
            ("loan_num", loan_num_str)
            ("amount",   amount_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct defnetloan_subcommand {
   string from_str;
   string loan_num_str;
   string amount_str;
   const name act_name{ N(defnetloan) };

   defnetloan_subcommand(CLI::App* actionRoot) {
      auto defnetloan = actionRoot->add_subcommand("defundnetloan", localized("Withdraw from a Network loan fund"));
      defnetloan->add_option("from",     from_str,     localized("Loan owner"))->required();
      defnetloan->add_option("loan_num", loan_num_str, localized("Loan ID"))->required();
      defnetloan->add_option("amount",   amount_str,  localized("Amount to be withdrawn"))->required();
      add_standard_transaction_options(defnetloan, "from@active");
      defnetloan->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("from",     from_str)
            ("loan_num", loan_num_str)
            ("amount",   amount_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(from_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct mvtosavings_subcommand {
   string owner_str;
   string rex_str;
   const name act_name{ N(mvtosavings) };

   mvtosavings_subcommand(CLI::App* actionRoot) {
      auto mvtosavings = actionRoot->add_subcommand("mvtosavings", localized("Move REX tokens to savings bucket"));
      mvtosavings->add_option("owner", owner_str, localized("REX owner"))->required();
      mvtosavings->add_option("rex",   rex_str,   localized("Amount of REX to be moved to savings bucket"))->required();
      add_standard_transaction_options(mvtosavings, "owner@active");
      mvtosavings->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("owner", owner_str)
            ("rex",   rex_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(owner_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct mvfrsavings_subcommand {
   string owner_str;
   string rex_str;
   const name act_name{ N(mvfrsavings) };

   mvfrsavings_subcommand(CLI::App* actionRoot) {
      auto mvfrsavings = actionRoot->add_subcommand("mvfromsavings", localized("Move REX tokens out of savings bucket"));
      mvfrsavings->add_option("owner", owner_str, localized("REX owner"))->required();
      mvfrsavings->add_option("rex",   rex_str,   localized("Amount of REX to be moved out of savings bucket"))->required();
      add_standard_transaction_options(mvfrsavings, "owner@active");
      mvfrsavings->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()
            ("owner", owner_str)
            ("rex",   rex_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(owner_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct updaterex_subcommand {
   string owner_str;
   const name act_name{ N(updaterex) };

   updaterex_subcommand(CLI::App* actionRoot) {
      auto updaterex = actionRoot->add_subcommand("updaterex", localized("Update REX owner vote stake and vote weight"));
      updaterex->add_option("owner", owner_str, localized("REX owner"))->required();
      add_standard_transaction_options(updaterex, "owner@active");
      updaterex->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()("owner", owner_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(owner_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct consolidate_subcommand {
   string owner_str;
   const name act_name{ N(consolidate) };

   consolidate_subcommand(CLI::App* actionRoot) {
      auto consolidate = actionRoot->add_subcommand("consolidate", localized("Consolidate REX maturity buckets into one that matures in 4 days"));
      consolidate->add_option("owner", owner_str, localized("REX owner"))->required();
      add_standard_transaction_options(consolidate, "owner@active");
      consolidate->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()("owner", owner_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(owner_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct rexexec_subcommand {
   string user_str;
   string max_str;
   const name act_name{ N(rexexec) };

   rexexec_subcommand(CLI::App* actionRoot) {
      auto rexexec = actionRoot->add_subcommand("rexexec", localized("Perform REX maintenance by processing expired loans and unfilled sell orders"));
      rexexec->add_option("user", user_str, localized("User executing the action"))->required();
      rexexec->add_option("max",  max_str,  localized("Maximum number of CPU loans, Network loans, and sell orders to be processed"))->required();
      add_standard_transaction_options(rexexec, "user@active");
      rexexec->callback([this] {
            fc::variant act_payload = fc::mutable_variant_object()
               ("user", user_str)
               ("max",  max_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(user_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

struct closerex_subcommand {
   string owner_str;
   const name act_name{ N(closerex) };

   closerex_subcommand(CLI::App* actionRoot) {
      auto closerex = actionRoot->add_subcommand("closerex", localized("Delete unused REX-related user table entries"));
      closerex->add_option("owner", owner_str, localized("REX owner"))->required();
      add_standard_transaction_options(closerex, "owner@active");
      closerex->callback([this] {
         fc::variant act_payload = fc::mutable_variant_object()("owner", owner_str);
         auto accountPermissions = get_account_permissions(tx_permission, {name(owner_str), config::active_name});
         send_actions({create_action(accountPermissions, config::system_account_name, act_name, act_payload)});
      });
   }
};

void get_account( const string& accountName, const string& coresym, bool json_format ) {
   fc::variant json;
   if (coresym.empty()) {
      json = call(get_account_func, fc::mutable_variant_object("account_name", accountName));
   }
   else {
      json = call(get_account_func, fc::mutable_variant_object("account_name", accountName)("expected_core_symbol", symbol::from_string(coresym)));
   }

   auto res = json.as<eosio::chain_apis::read_only::get_account_results>();
   if (!json_format) {
      asset staked;
      asset unstaking;

      if( res.core_liquid_balance.valid() ) {
         unstaking = asset( 0, res.core_liquid_balance->get_symbol() ); // Correct core symbol for unstaking asset.
         staked = asset( 0, res.core_liquid_balance->get_symbol() );    // Correct core symbol for staked asset.
      }

      std::cout << "created: " << string(res.created) << std::endl;

      if(res.privileged) std::cout << "privileged: true" << std::endl;

      constexpr size_t indent_size = 5;
      const string indent(indent_size, ' ');

      std::cout << "permissions: " << std::endl;
      unordered_map<name, vector<name>/*children*/> tree;
      vector<name> roots; //we don't have multiple roots, but we can easily handle them here, so let's do it just in case
      unordered_map<name, eosio::chain_apis::permission> cache;
      for ( auto& perm : res.permissions ) {
         if ( perm.parent ) {
            tree[perm.parent].push_back( perm.perm_name );
         } else {
            roots.push_back( perm.perm_name );
         }
         auto name = perm.perm_name; //keep copy before moving `perm`, since thirst argument of emplace can be evaluated first
         // looks a little crazy, but should be efficient
         cache.insert( std::make_pair(name, std::move(perm)) );
      }
      std::function<void (account_name, int)> dfs_print = [&]( account_name name, int depth ) -> void {
         auto& p = cache.at(name);
         std::cout << indent << std::string(depth*3, ' ') << name << ' ' << std::setw(5) << p.required_auth.threshold << ":    ";
         const char *sep = "";
         for ( auto it = p.required_auth.keys.begin(); it != p.required_auth.keys.end(); ++it ) {
            std::cout << sep << it->weight << ' ' << it->key.to_string();
            sep = ", ";
         }
         for ( auto& acc : p.required_auth.accounts ) {
            std::cout << sep << acc.weight << ' ' << acc.permission.actor.to_string() << '@' << acc.permission.permission.to_string();
            sep = ", ";
         }
         std::cout << std::endl;
         auto it = tree.find( name );
         if (it != tree.end()) {
            auto& children = it->second;
            sort( children.begin(), children.end() );
            for ( auto& n : children ) {
               // we have a tree, not a graph, so no need to check for already visited nodes
               dfs_print( n, depth+1 );
            }
         } // else it's a leaf node
      };
      std::sort(roots.begin(), roots.end());
      for ( auto r : roots ) {
         dfs_print( r, 0 );
      }

      auto to_pretty_net = []( int64_t nbytes, uint8_t width_for_units = 5 ) {
         if(nbytes == -1) {
             // special case. Treat it as unlimited
             return std::string("unlimited");
         }

         string unit = "bytes";
         double bytes = static_cast<double> (nbytes);
         if (bytes >= 1024 * 1024 * 1024 * 1024ll) {
             unit = "TiB";
             bytes /= 1024 * 1024 * 1024 * 1024ll;
         } else if (bytes >= 1024 * 1024 * 1024) {
             unit = "GiB";
             bytes /= 1024 * 1024 * 1024;
         } else if (bytes >= 1024 * 1024) {
             unit = "MiB";
             bytes /= 1024 * 1024;
         } else if (bytes >= 1024) {
             unit = "KiB";
             bytes /= 1024;
         }
         std::stringstream ss;
         ss << setprecision(4);
         ss << bytes << " ";
         if( width_for_units > 0 )
            ss << std::left << setw( width_for_units );
         ss << unit;
         return ss.str();
      };



      std::cout << "memory: " << std::endl
                << indent << "quota: " << std::setw(15) << to_pretty_net(res.ram_quota) << "  used: " << std::setw(15) << to_pretty_net(res.ram_usage) << std::endl << std::endl;

      std::cout << "net bandwidth: " << std::endl;
      if ( res.total_resources.is_object() ) {
         auto net_total = to_asset(res.total_resources.get_object()["net_weight"].as_string());

         if( net_total.get_symbol() != unstaking.get_symbol() ) {
            // Core symbol of nodeos responding to the request is different than core symbol built into cleos
            unstaking = asset( 0, net_total.get_symbol() ); // Correct core symbol for unstaking asset.
            staked = asset( 0, net_total.get_symbol() ); // Correct core symbol for staked asset.
         }

         if( res.self_delegated_bandwidth.is_object() ) {
            asset net_own =  asset::from_string( res.self_delegated_bandwidth.get_object()["net_weight"].as_string() );
            staked = net_own;

            auto net_others = net_total - net_own;

            std::cout << indent << "staked:" << std::setw(20) << net_own
                      << std::string(11, ' ') << "(total stake delegated from account to self)" << std::endl
                      << indent << "delegated:" << std::setw(17) << net_others
                      << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
         }
         else {
            auto net_others = net_total;
            std::cout << indent << "delegated:" << std::setw(17) << net_others
                      << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
         }
      }


      auto to_pretty_time = []( int64_t nmicro, uint8_t width_for_units = 5 ) {
         if(nmicro == -1) {
             // special case. Treat it as unlimited
             return std::string("unlimited");
         }
         string unit = "us";
         double micro = static_cast<double>(nmicro);

         if( micro > 1000000*60*60ll ) {
            micro /= 1000000*60*60ll;
            unit = "hr";
         }
         else if( micro > 1000000*60 ) {
            micro /= 1000000*60;
            unit = "min";
         }
         else if( micro > 1000000 ) {
            micro /= 1000000;
            unit = "sec";
         }
         else if( micro > 1000 ) {
            micro /= 1000;
            unit = "ms";
         }
         std::stringstream ss;
         ss << setprecision(4);
         ss << micro << " ";
         if( width_for_units > 0 )
            ss << std::left << setw( width_for_units );
         ss << unit;
         return ss.str();
      };


      std::cout << std::fixed << setprecision(3);
      std::cout << indent << std::left << std::setw(11) << "used:"      << std::right << std::setw(18) << to_pretty_net( res.net_limit.used ) << "\n";
      std::cout << indent << std::left << std::setw(11) << "available:" << std::right << std::setw(18) << to_pretty_net( res.net_limit.available ) << "\n";
      std::cout << indent << std::left << std::setw(11) << "limit:"     << std::right << std::setw(18) << to_pretty_net( res.net_limit.max ) << "\n";
      std::cout << std::endl;

      std::cout << "cpu bandwidth:" << std::endl;

      if ( res.total_resources.is_object() ) {
         auto cpu_total = to_asset(res.total_resources.get_object()["cpu_weight"].as_string());

         if( res.self_delegated_bandwidth.is_object() ) {
            asset cpu_own = asset::from_string( res.self_delegated_bandwidth.get_object()["cpu_weight"].as_string() );
            staked += cpu_own;

            auto cpu_others = cpu_total - cpu_own;

            std::cout << indent << "staked:" << std::setw(20) << cpu_own
                      << std::string(11, ' ') << "(total stake delegated from account to self)" << std::endl
                      << indent << "delegated:" << std::setw(17) << cpu_others
                      << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
         } else {
            auto cpu_others = cpu_total;
            std::cout << indent << "delegated:" << std::setw(17) << cpu_others
                      << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
         }
      }


      std::cout << std::fixed << setprecision(3);
      std::cout << indent << std::left << std::setw(11) << "used:"      << std::right << std::setw(18) << to_pretty_time( res.cpu_limit.used ) << "\n";
      std::cout << indent << std::left << std::setw(11) << "available:" << std::right << std::setw(18) << to_pretty_time( res.cpu_limit.available ) << "\n";
      std::cout << indent << std::left << std::setw(11) << "limit:"     << std::right << std::setw(18) << to_pretty_time( res.cpu_limit.max ) << "\n";
      std::cout << std::endl;

      if( res.refund_request.is_object() ) {
         auto obj = res.refund_request.get_object();
         auto request_time = fc::time_point_sec::from_iso_string( obj["request_time"].as_string() );
         fc::time_point refund_time = request_time + fc::days(3);
         auto now = res.head_block_time;
         asset net = asset::from_string( obj["net_amount"].as_string() );
         asset cpu = asset::from_string( obj["cpu_amount"].as_string() );
         unstaking = net + cpu;

         if( unstaking > asset( 0, unstaking.get_symbol() ) ) {
            std::cout << std::fixed << setprecision(3);
            std::cout << "unstaking tokens:" << std::endl;
            std::cout << indent << std::left << std::setw(25) << "time of unstake request:" << std::right << std::setw(20) << string(request_time);
            if( now >= refund_time ) {
               std::cout << " (available to claim now with 'eosio::refund' action)\n";
            } else {
               std::cout << " (funds will be available in " << to_pretty_time( (refund_time - now).count(), 0 ) << ")\n";
            }
            std::cout << indent << std::left << std::setw(25) << "from net bandwidth:" << std::right << std::setw(18) << net << std::endl;
            std::cout << indent << std::left << std::setw(25) << "from cpu bandwidth:" << std::right << std::setw(18) << cpu << std::endl;
            std::cout << indent << std::left << std::setw(25) << "total:" << std::right << std::setw(18) << unstaking << std::endl;
            std::cout << std::endl;
         }
      }

      if( res.core_liquid_balance.valid() ) {
         std::cout << res.core_liquid_balance->get_symbol().name() << " balances: " << std::endl;
         std::cout << indent << std::left << std::setw(11)
                   << "liquid:" << std::right << std::setw(18) << *res.core_liquid_balance << std::endl;
         std::cout << indent << std::left << std::setw(11)
                   << "staked:" << std::right << std::setw(18) << staked << std::endl;
         std::cout << indent << std::left << std::setw(11)
                   << "unstaking:" << std::right << std::setw(18) << unstaking << std::endl;
         std::cout << indent << std::left << std::setw(11) << "total:" << std::right << std::setw(18) << (*res.core_liquid_balance + staked + unstaking) << std::endl;
         std::cout << std::endl;
      }

      if( res.rex_info.is_object() ) {
         auto& obj = res.rex_info.get_object();
         asset vote_stake = asset::from_string( obj["vote_stake"].as_string() );
         asset rex_balance = asset::from_string( obj["rex_balance"].as_string() );
         std::cout << rex_balance.get_symbol().name() << " balances: " << std::endl;
         std::cout << indent << std::left << std::setw(11)
                   << "balance:" << std::right << std::setw(18) << rex_balance << std::endl;
         std::cout << indent << std::left << std::setw(11)
                   << "staked:" << std::right << std::setw(18) << vote_stake << std::endl;
         std::cout << std::endl;
      }

      if ( res.voter_info.is_object() ) {
         auto& obj = res.voter_info.get_object();
         string proxy = obj["proxy"].as_string();
         if ( proxy.empty() ) {
            auto& prods = obj["producers"].get_array();
            std::cout << "producers:";
            if ( !prods.empty() ) {
               for ( size_t i = 0; i < prods.size(); ++i ) {
                  if ( i%3 == 0 ) {
                     std::cout << std::endl << indent;
                  }
                  std::cout << std::setw(16) << std::left << prods[i].as_string();
               }
               std::cout << std::endl;
            } else {
               std::cout << indent << "<not voted>" << std::endl;
            }
         } else {
            std::cout << "proxy:" << indent << proxy << std::endl;
         }
      }
      std::cout << std::endl;
   } else {
      std::cout << fc::json::to_pretty_string(json) << std::endl;
   }
}

CLI::callback_t header_opt_callback = [](CLI::results_t res);

