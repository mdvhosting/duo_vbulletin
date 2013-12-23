<?php

/*******************************************************************/
/*                        Duo for vBulletin                        */
/*******************************************************************/
/* Description: This package allows you to add Duo security        */
/* functionality to your vBulletin community. Generally this is    */
/* useful for administrators and moderators but depending on your  */
/* community could have any number of uses.                        */
/*                                                                 */
/* Author: Matt V.                                                 */
/* Version: v.3.0                                                  */
/* For vBulletin: v.3.4+, v.4.x                                    */
/*******************************************************************/

// The version of this script (best not to edit!)
$script_version = "3.0";

define('THIS_script', 'DuoSecurity');

switch($_GET['id'])
{
	/*
	The fetch_methods action is where we execute the "preauth" request. This is where we get the 
	list of methods available for the user and send back a nice list for them to choose from.
	*/
	case "fetch_methods":
		$curdir = getcwd();
		chdir("../");
		require_once("global.php");
		chdir($curdir);
		
		// Get the user id
		$user_id = $_GET['userid'];
		
		// Make sure we got a valid id
		if(intval($user_id) > 0)
		{
			// Assemble the header to POST to Duo
			$duo_header = "POST\n" . $vbulletin->options['duosecurity_api_host'] . "\n/rest/v1/preauth.json\nuser=" . $vbulletin->options['duosecurity_bb_prefix'] . $user_id;
			
			// Hash the header
			$duo_header_enc = hash_hmac("sha1", $duo_header, $vbulletin->options['duosecurity_skey']);
			
			// Build the cURL options we need
			$curl_options = array(CURLOPT_URL => "https://" . $vbulletin->options['duosecurity_api_host'] . "/rest/v1/preauth.json",
								CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
								CURLOPT_USERPWD => $vbulletin->options['duosecurity_ikey'] . ":" . $duo_header_enc,
								CURLOPT_RETURNTRANSFER => TRUE,
								CURLOPT_FORBID_REUSE => TRUE,
								CURLOPT_FRESH_CONNECT => TRUE,
								CURLOPT_POST => TRUE,
								CURLOPT_POSTFIELDS => "user=" . $vbulletin->options['duosecurity_bb_prefix'] . $user_id
			);
			
			// Initialize cURL and set the options
			$curl_handle = curl_init();
			curl_setopt_array($curl_handle, $curl_options);
			
			// Execute the cURL request and check the result
			if(!($curl_result = curl_exec($curl_handle)))
			{
				// There was an error, so we'll let the user know what happened
				$curl_error = curl_error($curl_handle);
				echo construct_phrase($vbphrase['duosecurity_error_curl_x'], $curl_error);
			}
			else
			{
				// The request was successful, so let's proceed to decoding the response
				$duo_result = json_decode($curl_result, true);
				
				// Check the result of the request
				if($duo_result['stat'] == "OK" && $duo_result['response']['result'] == "auth")
				{
					// The request was "ok" and we're able to "auth" the user
					
					// Expand the authentication options from the "prompt" text
					// Note: This is the best way to get the options, as opposed to the factors list. The factors list
					// does not include the phone number, so users with multiple numbers would be at a loss. By using
					// the prompt text we can use that phone number for our custom prompt. We also want to split out
					// which option number (1, 2, etc.) corresponds to which factor (phone1, phone2, etc.)
					preg_match_all("/([1-9])\. (.+) to (.+) ?\(?(.*)\)?\\n/", $duo_result['response']['prompt'], $auth_methods, PREG_SET_ORDER);
					
					// Now we show the prompt to the user
					echo $vbphrase['duosecurity_auth_prompt'] . "<br /><br />";
					
					foreach($auth_methods as $k => $v)
					{
						// For each factor, we output a button. We use the information from the prompt splicing above to
						// label the buttons and then use the factor for our JavaScript function.
						?>
						<div class="duo_method_row" onClick="begin_auth('<?php echo $user_id; ?>', '<?php echo $duo_result['response']['factors'][$v[1]]; ?>')">
							<?php echo $v[2] . "<br /><span class=\"duo_method_row_small\">" . $v[3] . "</span>"; ?>
						</div>
						<?php
					}
					// We also provide a textbox for a passcode. This is for people who already have passcodes, 
					// have a hardware token, or use the Duo Mobile application to get a code.
					echo "<br />" . $vbphrase['duosecurity_passcode_prompt'] . "<br />";
					?>
					<input type="text" id="duo_passcode" name="duo_passcode" size="10" /> <input type="button" id="duo_submit" name="duo_submit" onClick="passcode_auth('<?php echo $user_id; ?>')" value="<?php echo $vbphrase['duosecurity_next']; ?>" />
					<?php
				}
				elseif($duo_result['stat'] == "OK" && $duo_result['response']['result'] == "allow")
				{
					// The request was "ok" and we need to allow the user due to a secondary-factor bypass
					
					// Encode the Duo key to send back to vBulletin
					$duo_key = base64_encode(crypt($user_id, '$5$' . md5($vbulletin->options['duosecurity_skey'])));
					
					echo $vbphrase['duosecurity_success_bypass'];
					?>
					<script auto_exec type="text/javascript">
						document.getElementById("duo_key").value = "<?php echo $duo_key; ?>";
						setTimeout(auth_submit(), 3000);
					</script>
					<?php
				}
				elseif($duo_result['stat'] == "OK" && $duo_result['response']['result'] == "enroll")
				{
					// The request was "ok" and we need to forward the user for enrollment
					
					// Pull out the enrollment URL
					$matched_url = array();
					preg_match("/https[^\s]+/", $duo_result['response']['status'], $matched_url);
					
					// Show the user an enrollment message
					echo construct_phrase($vbphrase['duosecurity_enroll_prompt_x'], $matched_url[0]);
				}
				else
				{
					// Generally when the result is a failure for this stage of the process the user is not an
					// active Duo-enabled user.
					echo $vbphrase['duosecurity_not_available'];
				}
			}
		}
		else
		{
			// If the user id was invalid, let the user know. This shouldn't happen...
			echo $vbphrase['duosecurity_error_userid'];
		}
	break;
	
	/*
	The do_auth method action is where we actually push the authentication request to Duo. It's worth
	noting that we are using the asynchronous type of auth request and will later use the "poll" method.
	*/
	case "do_auth":
		$curdir = getcwd();
		chdir("../");
		require_once("global.php");
		chdir($curdir);
		
		$user_id = $_POST['userid'];
		$duo_type = preg_replace("/[0-9]/", "", $_POST['duo_factor']);
		$duo_factor = $_POST['duo_factor'];
		$duo_passcode = $_POST['duo_passcode'];
		
		// Make sure we got a valid id
		if(intval($user_id) > 0)
		{
			// Make sure we got a passcode from the user if they're using the passcode factor
			if($duo_type != "passcode" || ($duo_type == "passcode" && strlen($duo_passcode) > 0))
			{
				// Get the user's clean IPv4 address
				$_SERVER['HTTP_X_FORWARDED_FOR'] = str_replace("::ffff:", "", preg_replace('/,.+/', '', $_SERVER['HTTP_X_FORWARDED_FOR']));
				
				$_SERVER['REMOTE_ADDR'] = str_replace("::ffff:", "", preg_replace('/,.+/', '', $_SERVER['REMOTE_ADDR']));
				
				if($_SERVER['HTTP_X_FORWARDED_FOR'] != '')
				{
					$_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
				}
				
				// Build an array of options which will be POST'd to Duo
				$post_fields = array();
				// For the passcode method we don't need to use the asynchronous method since Duo will 
				// respond with a result right away.
				if($duo_type != "passcode") { $post_fields["async"] = "true"; }
				$post_fields["factor"] = $duo_type;
				$post_fields["ipaddr"] = $_SERVER['REMOTE_ADDR'];
				$post_fields["user"] = $vbulletin->options['duosecurity_bb_prefix'] . $user_id;
				
				// Append the right fields based on factor type
				switch($duo_type)
				{
					case "push":
					case "sms":
						// This is a fun trick. For the push and sms methods, Duo requires you specify a "phone" to use.
						// This makes sense I suppose, but the annoying thing is the factor will be "sms1" with no
						// reference to what phone should be used. So, we just take the last character of the factor, 
						// "1" in the case of "sms1", and append it to "phone".
						$post_fields["phone"] = "phone" . substr($duo_factor, strlen($duo_factor)-1);
					break;
					
					case "phone":
						$post_fields["phone"] = $duo_factor;
					break;
					
					case "passcode":
						// If using a passcode, we need to POST the code.
						$post_fields["code"] = $duo_passcode;
					break;
				}
				
				// For the request signature to be valid, we need the fields to be in alphabetical order
				ksort($post_fields);
				
				// Now we build a textual representation of the sorted array
				$header_post_fields = "";
				foreach($post_fields as $k => $v)
				{
					$header_post_fields .= (strlen($header_post_fields) > 0?"&":"") . $k . "=" . $v;
				}
				
				// Assemble the header to POST to Duo
				$duo_header = "POST\n" . $vbulletin->options['duosecurity_api_host'] . "\n/rest/v1/auth.json\n" . $header_post_fields;
				
				// Hash the header
				$duo_header_enc = hash_hmac("sha1", $duo_header, $vbulletin->options['duosecurity_skey']);
				
				// Build the cURL options we need
				$curl_options = array(CURLOPT_URL => "https://" . $vbulletin->options['duosecurity_api_host'] . "/rest/v1/auth.json",
									CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
									CURLOPT_USERPWD => $vbulletin->options['duosecurity_ikey'] . ":" . $duo_header_enc,
									CURLOPT_RETURNTRANSFER => TRUE,
									CURLOPT_FORBID_REUSE => TRUE,
									CURLOPT_FRESH_CONNECT => TRUE,
									CURLOPT_POST => TRUE,
									CURLOPT_POSTFIELDS => $header_post_fields
				);
				
				// Initialize cURL and set the options
				$curl_handle = curl_init();
				curl_setopt_array($curl_handle, $curl_options);
				
				// Execute the cURL request and check the result
				if(!($curl_result = curl_exec($curl_handle)))
				{
					// There was an error, so we'll let the user know what happened
					$curl_error = curl_error($curl_handle);
					echo construct_phrase($vbphrase['duosecurity_error_curl_x'], $curl_error);
				}
				else
				{
					// The request was successful, so let's proceed to decoding the response
					$duo_result = json_decode($curl_result, true);
					
					// Make sure we got an "OK" back before proceeding
					if($duo_result['stat'] == "OK")
					{
						// If we got a txid back, we're in asynchronous mode and need to show the appropriate GUI to the
						// user. This GUI shows the status of the request updated ever 2-3 seconds.
						if(strlen($duo_result['response']['txid']) > 0)
						{
							// Echo the dynamic GUI
							?>
							<div id="duo_dynamic_title"><?php echo $vbphrase['duosecurity_auth_begin']; ?></div>
							<br /><br />
							<img src="<?php echo $vbulletin->options['duosecurity_image_path']; ?>loading_large.gif" width="64" height="64" />
							<?php
								// If the user has requested to use an SMS passcode, we need to give them a place to enter it
								if($duo_type != "push" && $duo_type != "phone")
								{
									echo'<br /><br />' . $vbphrase['duosecurity_passcode'] . '<br /><input type="text" id="duo_passcode" name="duo_passcode" size="10" /> <input type="button" id="duo_submit" name="duo_submit" onClick="passcode_auth(\'' . $user_id . '\')" value="' . $vbphrase['duosecurity_next'] . '" />';
								}
							?>
							<script auto_exec type="text/javascript">
								setTimeout(poll_duo("<?php echo $duo_result['response']['txid']; ?>", "<?php echo $user_id; ?>"), 2000);
							</script>
							<?php
						}
						elseif($duo_result['response']['result'] == "allow")
						{
							// If we got an "allow" back, that means the user has been approved by Duo
							
							// Encode the Duo key to send back to vBulletin
							$duo_key = base64_encode(crypt($user_id, '$5$' . md5($vbulletin->options['duosecurity_skey'])));
							
							echo $vbphrase['duosecurity_success'];
							?>
							<script auto_exec type="text/javascript">
								document.getElementById("duo_key").value = "<?php echo $duo_key; ?>";
								auth_submit();
							</script>
							<?php
						}
						elseif($duo_result['response']['result'] == "deny")
						{
							// If we got a "deny" back, that means the user failed Duo verification
							echo $vbphrase['duosecurity_error_failed'] . "<br /><br />" . $vbphrase['duosecurity_try_again'];
						}
					}
					else
					{
						// If we didn't get an "OK" back, there was a problem with our request. This shouldn't happen...
						echo $vbphrase['duosecurity_error_generic'];
					}
				}
			}
			else
			{
				// The user selected to authenticate using a passcode but left the passcode blank
				echo $vbphrase['duosecurity_error_passcode'] . "<br /><br />" . $vbphrase['duosecurity_try_again'];
			}
		}
		else
		{
			// If the user id was invalid, let the user know. This shouldn't happen...
			echo $vbphrase['duosecurity_error_userid'];
		}
	break;
	
	/*
	The poll_duo action is where we request status updates from Duo for asynchronous authentication
	requests. We check about every 2-3 seconds for a decision and update the GUI with the request's
	latest status.
	*/
	case "poll_duo":
		$curdir = getcwd();
		chdir("../");
		require_once("global.php");
		chdir($curdir);
		
		$user_id = $_POST['userid'];
		$txid = $_POST['txid'];
		
		// Check if we have a valid transaction id and user id
		if(strlen($txid) > 0 && $user_id > 0)
		{
			// Assemble the header to POST to Duo
			$duo_header = "GET\n" . $vbulletin->options['duosecurity_api_host'] . "\n/rest/v1/status\ntxid=" . $txid;
			
			// Hash the header
			$duo_header_enc = hash_hmac("sha1", $duo_header, $vbulletin->options['duosecurity_skey']);
			
			// Build the cURL options we need
			$curl_options = array(CURLOPT_URL => "https://" . $vbulletin->options['duosecurity_api_host'] . "/rest/v1/status?txid=" . $txid,
								CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
								CURLOPT_USERPWD => $vbulletin->options['duosecurity_ikey'] . ":" . $duo_header_enc,
								CURLOPT_RETURNTRANSFER => TRUE,
								CURLOPT_FORBID_REUSE => TRUE,
								CURLOPT_FRESH_CONNECT => TRUE
			);
			
			// Initialize cURL and set the options
			$curl_handle = curl_init();
			curl_setopt_array($curl_handle, $curl_options);
			
			// Execute the cURL request and check the result
			if(!($curl_result = curl_exec($curl_handle)))
			{
				// There was an error, so we'll let the user know what happened
				$curl_error = curl_error($curl_handle);
				echo construct_phrase($vbphrase['duosecurity_error_curl_x'], $curl_error);
			}
			else
			{
				// The request was successful, so let's proceed to decoding the response
				$duo_result = json_decode($curl_result, true);
				
				// Check the result we got back from Duo
				if($duo_result['stat'] == "OK" && $duo_result['response']['result'] == "allow")
				{
					// If we got an "allow" back, that means the user has been approved by Duo
					
					// Encode the Duo key to send back to vBulletin
					$duo_key = base64_encode(crypt($user_id, '$5$' . md5($vbulletin->options['duosecurity_skey'])));
					
					?>
					<script auto_exec type="text/javascript">
						document.getElementById("duo_dynamic").innerHTML = "<?php echo $vbphrase['duosecurity_success']; ?>";
						document.getElementById("duo_key").value = "<?php echo $duo_key; ?>";
						auth_submit();
					</script>
					<?php
				}
				elseif($duo_result['stat'] == "OK" && $duo_result['response']['result'] == "deny")
				{
					// If we got a "deny" back, that means the user failed Duo verification
					?>
					<script auto_exec type="text/javascript">
						document.getElementById("duo_dynamic").innerHTML = "<?php echo $vbphrase['duosecurity_denied']; ?><br /><br /><?php echo $vbphrase['duosecurity_try_again']; ?>";
					</script>
					<?php
				}
				elseif($duo_result['stat'] == "OK")
				{
					// If we got an "OK" back with no result, it means the request is still in progress. So,
					// we simply update the GUI with the latest status message.
					?>
					<script auto_exec type="text/javascript">
						document.getElementById("duo_dynamic_title").innerHTML = "<?php echo $duo_result['response']['status']; ?>";
						setTimeout(poll_duo("<?php echo $txid; ?>", "<?php echo $user_id; ?>"), 3000);
					</script>
					<?php
				}
				elseif($duo_result['stat'] == "FAIL")
				{
					// If we got a "FAIL" back, the authentication request failed
					?>
					<script auto_exec type="text/javascript">
						document.getElementById("duo_dynamic").innerHTML = "<?php echo $vbphrase['duosecurity_error_failed']; ?><br /><br /><?php echo $vbphrase['duosecurity_try_again']; ?>";
					</script>
					<?php
				}
				else
				{
					// We haven't gotten a useful response, so we just schedule another status check in 3 seconds
					?>
					<script auto_exec type="text/javascript">
						setTimeout(poll_duo("<?php echo $txid; ?>", "<?php echo $user_id; ?>"), 3000);
					</script>
					<?php
				}
			}
		}
		else
		{
			// If the transaction id or user id was invalid, let the user know. This shouldn't happen...
			echo $vbphrase['duosecurity_invalid_txid_userid'];
		}
	break;
	
	/*
	The default action is where we show the main interface for the Duo authentication flow. From here,
	we update the GUI dynamically as different actions occur.
	*/
	default:
		// Get the user ID from vBulletin
		$user_id = $vbulletin->userinfo['userid'];
		?>
		<html>
		<head>
			<title><?php echo $vbphrase['duosecurity_title'] . $vbulletin->options['bbtitle']; ?></title>
			
			<link href="<?php echo $vbulletin->options['duosecurity_web_path']; ?>duo_style.css" rel="stylesheet" type="text/css">
			
			<script src="//ajax.googleapis.com/ajax/libs/dojo/1.8.1/dojo/dojo.js" data-dojo-config="parseOnLoad: false, async: true"></script>
			
			<script>
				require(["dojo/fx",
					"dojo/on"]);
				
				require(["require",
					"dojo/_base/array",
					"dojo/_base/config",
					"dojo/dom",
					"dojo/_base/kernel",
					"dojo/ready",
					"dojo/_base/window",
					"dojo/_base/fx",
					"dijit/registry",
					"dojo/request/xhr",
					"dojo/parser"],
					function(require, array, config, dom, kernel, ready, window, fx, registry, xhr, parser){
						ready(function(){
							// When Duo is ready parse the page
							parser.parse();
							
							// Send the initial (preauth) request to Duo for this user's options
							xhr("<?php echo $vbulletin->options['duosecurity_web_path']; ?>duo_rest.php?id=fetch_methods&userid=<?php echo $user_id; ?>").then(function(text)
							{
								eval_scripts(text);
								document.getElementById("duo_dynamic").innerHTML = text;
							}, function(err)
							{
								document.getElementById("duo_dynamic").innerHTML = err;
							});
						});
					}
				);
			</script>
			
			<script type="text/javascript">
				/*
				Purpose: This function allows us to send JavaScript back in AJAX responses and have it executed.
				Arguments:
				- plain_html : The HTML to look within for JavaScript to execute
				*/
				function eval_scripts(plain_html)
				{
					try
					{
						if(plain_html != '')
						{
							var script = "";
							plain_html = plain_html.replace(/<script auto_exec[^>]*>([\s\S]*?)<\/script>/gi, function(){
								if (plain_html !== null) script += arguments[1] + '\n';
								return '';
							});
							
							if(script) (window.execScript) ? window.execScript(script) : window.setTimeout(script, 0);
						}
						return '';
					}
					catch(e)
					{
						return '';
					}
				}
				
				/*
				Purpose: This function is essentially used to reset the interface after a failed Duo attempt.
				*/
				function fetch_methods()
				{
					require(["dojo/request/xhr", "dojo/dom", "dojo/domReady!"],
						function(xhr, dom)
						{
							xhr("<?php echo $vbulletin->options['duosecurity_web_path']; ?>duo_rest.php?id=fetch_methods&userid=<?php echo $user_id; ?>", {
								method: "GET"
							}).then(function(data){
								eval_scripts(data);
								dom.byId("duo_dynamic").innerHTML = data;
							}, function(err){
								dom.byId("duo_dynamic").innerHTML = "<?php echo construct_phrase($vbphrase['duosecurity_error_generic_x'], "A"); ?>";
							});
						}
					);
				}
				
				/*
				Purpose: This function begins the authentication process when a user clicks a method or enters a passcode.
				Arguments:
				- vbul_userid : The user's vBulletin user ID
				- duo_factor : The factor the user would like to use (push1, phone1, sms1, etc.)
				- duo_passcode : The passcode the user entered, if applicable
				*/
				function begin_auth(vbul_userid, duo_factor, duo_passcode)
				{
					require(["dojo/request/xhr", "dojo/dom", "dojo/domReady!"],
						function(xhr, dom)
						{
							dom.byId("duo_dynamic").innerHTML = "<div id=\"duo_dynamic_title\"><?php echo $vbphrase['duosecurity_auth_begin']; ?></div><br /><br /><img src=\"<?php echo $vbulletin->options['duosecurity_image_path']; ?>loading_large.gif\" width=\"64\" height=\"64\" />";
							
							xhr("<?php echo $vbulletin->options['duosecurity_web_path']; ?>duo_rest.php?id=do_auth", {
								method: "POST",
								data: {
									userid: vbul_userid,
									duo_factor: duo_factor,
									duo_passcode: duo_passcode
								}
							}).then(function(data){
								eval_scripts(data);
								dom.byId("duo_dynamic").innerHTML = data;
							}, function(err){
								dom.byId("duo_dynamic").innerHTML = "<?php echo construct_phrase($vbphrase['duosecurity_error_generic_x'], "B"); ?>";
							});
						}
					);
				}
				
				/*
				Purpose: This function sends a poll request to Duo to check on the request's status.
				Arguments:
				- txid : The Duo transaction ID to check
				- vbul_userid : The user's vBulletin user ID
				*/
				function poll_duo(txid, vbul_userid)
				{
					require(["dojo/request/xhr", "dojo/dom", "dojo/domReady!"],
						function(xhr, dom)
						{
							xhr("<?php echo $vbulletin->options['duosecurity_web_path']; ?>duo_rest.php?id=poll_duo", {
								method: "POST",
								data: {
									txid: txid,
									userid: vbul_userid
								}
							}).then(function(data){
								eval_scripts(data);
							}, function(err){
								dom.byId("duo_dynamic").innerHTML = "<?php echo construct_phrase($vbphrase['duosecurity_error_generic_x'], "C"); ?>";
							});
						}
					);
				}
				
				/*
				Purpose: This function starts a passcode authentication request.
				Arguments:
				- vbul_userid : The user's vBulletin user ID
				*/
				function passcode_auth(vbul_userid)
				{
					require(["dojo/request/xhr", "dojo/dom", "dojo/domReady!"],
						function(xhr, dom)
						{
							xhr("<?php echo $vbulletin->options['duosecurity_web_path']; ?>duo_rest.php?id=do_auth", {
								method: "POST",
								data: {
									userid: vbul_userid,
									duo_factor: "passcode",
									duo_passcode: dom.byId("duo_passcode").value
								}
							}).then(function(data){
								dom.byId("duo_dynamic").innerHTML = data;
								eval_scripts(data);
							}, function(err){
								dom.byId("duo_dynamic").innerHTML = "<?php echo construct_phrase($vbphrase['duosecurity_error_generic_x'], "D"); ?>";
							});
						}
					);
				}
				
				/*
				Purpose: This function simply submits the form to vBulletin after Duo authentication is complete.
				*/
				function auth_submit()
				{
					the_form = document.getElementById('duo_form');
					if(the_form)
					{
						the_form.submit();
					}
				}
			</script>
		</head>
		<body>
			<div id="body_div">
				<table id="body_table">
				<tr>
					<td class="body_table_left">
						<img src="<?php echo $vbulletin->options['duosecurity_image_path']; ?>site_logo.png" width="280" height="105" alt="" /><br /><br />
						<img src="<?php echo $vbulletin->options['duosecurity_image_path']; ?>padlock.png" width="128" height="128"  alt="" /><br />
						<br />
						<?php
							echo "v." . $script_version;
							
							if($vbulletin->options['duosecurity_showpoweredby'])
							{
								?>
								<br /><br />
								<em><?php echo $vbphrase['duosecurity_powered_by']; ?></em><br />
								<a href="http://www.duosecurity.com" target="_blank">
									<img src="<?php echo $vbulletin->options['duosecurity_image_path']; ?>duo_logo.png" width="100" height="17" />
								</a>
								<?php
							}
						?>
					</td>
					<td class="body_table_right">
						<div id="duo_dynamic">
							<?php echo $vbphrase['duosecurity_loading']; ?>
						</div>
					</td>
				</tr>
				</table>
			</div>
			
			<form id="duo_form" action="login.php" method="POST">
				<input type="hidden" name="do" id="do" value="login" />
				<input type="hidden" name="vb_login_username" id="vb_login_username" value="<?php echo $vbulletin->GPC['vb_login_username']; ?>" />
				<input type="hidden" name="vb_login_md5password" id="vb_login_md5password" value="<?php echo $vbulletin->GPC['vb_login_md5password']; ?>" />
				<input type="hidden" name="vb_login_md5password_utf" id="vb_login_md5password_utf" value="<?php echo $vbulletin->GPC['vb_login_md5password_utf']; ?>" />
				<input type="hidden" name="postvars" id="postvars" value="<?php echo $vbulletin->GPC['postvars']; ?>" />
				<input type="hidden" name="cookieuser" id="cookieuser" value="<?php echo $vbulletin->GPC['cookieuser']; ?>" />
				<input type="hidden" name="logintype" id="logintype" value="<?php echo $vbulletin->GPC['logintype']; ?>" />
				<input type="hidden" name="cssprefs" id="cssprefs" value="<?php echo $vbulletin->GPC['cssprefs']; ?>" />
				<input type="hidden" name="url" id="url" value="<?php echo $vbulletin->url; ?>" />
				<input type="hidden" name="duo_key" id="duo_key" value="" />
			</form>
		</body>
		</html>
		<?php
	break;
}

?>