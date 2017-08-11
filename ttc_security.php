<?php
	
	/*
	 Plugin Name: TimesToCome Security Plugin
	 Version: 2.7
	 Plugin URI:  http://herselfswebtools.com/2008/06/wordpress-security-plugin-block-scrapers-hackers-and-more.html
	 Description: Security plugin for Wordpress
	 Author: Linda MacPhee-Cobb
	 Author URI: http://timestocome.com
	 */
	
	
	
	// ************************************************************************************************************
	//  NOTES TO USERS:	
	// Instead of an error page, bots are now re-routed to main page  
	// if you'd rather send bots to error pages see notes below
	//
	// to prevent yourself from being blocked change 127.0.0.1 to your ip ~ line 120 or so
	//
	// ************************************************************************************************************
	// NOTES TO CODERS:
	// Several people have asked to use this as a base to make their own security plugins
        // Please feel free - you don't need my permission. I wrote this because I needed it and 
        // if you create a better one I think that is wonderful. 
        //
        // Consider this code to be under the MIT license http://en.wikipedia.org/wiki/MIT_License
        //
        // If you do write a new improved version let me know I'll be happy post a link on the website.
        // ************************************************************************************************************
	

// ************************************************************************************************************
	//version 2.5 fixes menu options for wp 3.0
// ************************************************************************************************************
	//Feb. 2011 version 2.6 clean up, speed up,  
// ************************************************************************************************************
	//Jul 2011 fix requests and accepts not being stored
//************************************************************************************************************

		
	// globals
        $wpdb;
	$ttc_wpdb_prefix = $wpdb->prefix;	

	// server variables
	$http_accept = $_SERVER['HTTP_ACCEPT'];
	$http_remote_addr = $_SERVER['REMOTE_ADDR'];
	$http_local_addr = $_SERVER['SERVER_ADDR'];
	$http_user_agent = $_SERVER['HTTP_USER_AGENT'];
	$request_time = $_SERVER['REQUEST_TIME'];
	$request_uri = $_SERVER['REQUEST_URI'];
	$request_method = $_SERVER['REQUEST_METHOD'];


		
	// ttc variables
	$log_table_name = $ttc_wpdb_prefix . "ttc_security_log";
	$ip_table_name = $ttc_wpdb_prefix . "ttc_ip_blacklist";
	$agent_table_name = $ttc_wpdb_prefix . "ttc_agent_blacklist";
	$request_table_name = $ttc_wpdp_prefix . "ttc_request_blacklist";



	// check out who is visiting us
	function ttc_security()
	{
		// database info
		global $wpdb;	
		global $ttc_wpdb_prefix;
		global $log_table_name;
		global $ip_table_name;
		global $agent_table_name;
		global $request_table_name;
	
				
		// server variables
		global $http_accept;
		global $http_remote_addr;
		global $http_local_addr;
		global $http_user_agent;
		global $request_time;
		global $request_uri;
		global $request_method;
		
		// local variables
		$blacklisted = 0;
		


		///*********************************************
		//  does this need to be done each time?
		///*********************************************	
 		// create tables if they don't already exist
		 if (($wpdb->get_var("SHOW TABLES LIKE '$blacklist_table_name'") != $blacklist_table_name ) || 
			($wpdb->get_var("SHOW TABLES LIKE '$ip_table_name'") != $ip_table_name ) ||
			($wpdb->get_var("SHOW TABLES LIKE '$agent_table_name'") != $agent_table_name ) ||
			 ($wpdb->get_var("SHOW TABLES LIKE '$request_table_name'") != $request_table_name )){

			 ttc_security_install();
		 }



		 
		////********************************************		
		// Note: faster and safer to pull all from db and loop through data using php for matches
		// than it is to prep input, (sanitize and clean up) and use MySql matching
		
		// Note: tried === instead of tacking x on front of string but only matches in first position
		// and we want matches any where in the string
		


		// check for banned ip number
		if ( $blacklisted == 0 ){
			$sql = "SELECT ip FROM $ip_table_name";
			$ip_black_list = $wpdb->get_results( $sql );
			
			foreach ( $ip_black_list as $blacklisted_ip ){
				$bad_ip = $blacklisted_ip->ip;				
				
				// check for exact match only OR use code below to block sections
				//if ( strcasecmp( $http_remote_addr, $bad_ip ) == 0 ){  $blacklisted = 1;  }
				
				//check for partial matches so we can block blocks of troublesome ip numbers
				// hack so null doesn't equal a match
				$hacked_http_remote_addr = "x" . $http_remote_addr; 
				if ((strpos ( $hacked_http_remote_addr, $bad_ip, 1 )) == 1 ){
					$blacklisted = 1;
				}	
			}
		}
		
		
		
		// check for banned user agents and also for blank user agents
		if ( $blacklisted == 0 ){
			$sql = "SELECT agent FROM $agent_table_name";
			$agent_black_list = $wpdb->get_results ( $sql );

			//php reads 0 if not found, or if first position matches, this is a hack around that. PHP should return -1 not NULL !!!		
			$hacked_http_user_agent = "x" . $http_user_agent; 
			foreach ( $agent_black_list as $blacklisted_agent ){
				$bad_agent = $blacklisted_agent->agent;			
				
				if ( strpos ( $hacked_http_user_agent, $bad_agent ) > 0  ){
					$blacklisted = 2;
				}else if ( strlen ($hacked_http_user_agent) < 2 ){
					$blacklisted = 3;
				}
			}
		}
		
		
		// check for funny business in url
		if ( $blacklisted == 0 ){
			
			$sql = "SELECT request from $request_table_name";
			$request_black_list = $wpdb->get_results ( $sql );
			
			$hacked_request_uri = "x" . $request_uri;  // php reads 0 if no match and 0 if first position, this is a hack around that.
			foreach ( $request_black_list as $blacklisted_request ){
				$bad_request = $blacklisted_request->request;
				if ( strpos ( $hacked_request_uri, $bad_request ) > 0  ){
					$blacklisted = 14;
				}
			}
		}
		
		
		
		
		
				
		//**************************************************************************************************************
		// don't ban ourselves Change 127.0.0.1 to your ip number if you find yourself getting banned.
		//**************************************************************************************************************
		// don't ban ourselves....
		if ( $http_local_addr == $http_remote_addr ){ $blacklisted = 0;
		}else if ( $http_remote_addr == "127.0.0.1" ){ $blacklisted = 0; }  //////  change 127.0.0.1 to your ip to prevent self banishment
		
		



		//update our log files
		// if code is one  update log files
		// else update log file and ip file
		
		if ( $blacklisted == 0 ){
			
			// do nothing all is right and wonderful in the world
		$blacklisted = 0;
			

		}else if ( $blacklisted == 1 ){						// already blacklisted ip here so just add to log
			
			// too many to log, log entries growing too fast 
			//ttc_add_to_security_log(   $blacklisted );			//  add to log
			
			$code = "Sorry but you are listed on our ip blacklist";
			global $wpdb;
			
			//*************************************************************************************************************
			// this sends bots to main page you can create a custom page for bots and send them there if you'd rather			
			//*************************************************************************************************************
			// send rejections back to main site page
			$host  = $_SERVER['HTTP_HOST'];
			$uri   = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
			header("Location: http://$host$uri");
			
			exit();
			
		}else if ( $blacklisted > 1 ) {
			
			ttc_add_to_security_log(  $blacklisted );			// add to log
			ttc_add_to_security_blacklist( $http_remote_addr );	// add to our ip blacklist
			
			
			if (( $blacklisted == 2 )||( $blacklisted == 3 )){
				$code = "Your user agent is blacklisted. <br />\nIf you are using a web browser check your computer for spyware and viruses.";
			}else if ( $blacklisted == 11 ){
				$code = "Spamhaus listed spammer";
			}else if ( $blacklisted == 12 ){
				$code = "Spamhaus listed exploiter";
			}else if ( $blacklisted == 14 ){
				$code = "Attempted script or similar";
			}

			
			//*************************************************************************************************************
			// this sends bots to main page you can create a custom page for bots and send them there if you'd rather			
			//*************************************************************************************************************			
			$host  = $_SERVER['HTTP_HOST'];
			$uri   = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
			header("Location: http://$host$uri");
			
			
			exit();
			
		}
	}
	
	
	
	
	//  add any funny stuff to security log
	function ttc_add_to_security_log( $error )
	{
		// wordpress db info
		global $wpdb;
		global $ttc_wpdb_prefix;

		// server variables
		global $log_table_name;
		global $request_time;
		global $http_accept;
		global $http_user_agent;
		global $http_remote_addr;
		global $request_uri;
		
		
		// wtf? accept statements coming in at over 255 chars?  Prevent sql errors and any funny business
		// by shortening anything from user to 200 chars if over 255 
		if ( strlen($request_uri ) > 200 ){ $email = substr ($request_uri, 0, 200 ); }
		if ( strlen($http_accept ) > 200 ) { $http_accept = substr ( $http_accept, 0, 200 ); }
		if ( strlen($http_user_agent ) > 200 ) { $http_user_agent = substr ( $http_user_agent, 0, 200 ); }
		
		
		// clean input for database
		$http_accept = htmlentities($http_accept);
		$http_user_agent = htmlentities($http_user_agent);
		$http_remote_addr = htmlentities($http_remote_addr);
		$request_uri = htmlentities($request_uri);
		
		// ok now stuff the info into the log files in the db
		$sql = "INSERT INTO " . $log_table_name . " ( ip, problem, accept, agent, request, day ) 
		VALUES ( '$http_remote_addr', '$error', '$http_accept', '$http_user_agent', '$request_uri', NOW() )";
		$result = $wpdb->query( $sql );
		
	}
	
	
	//  automatically black list bozos ip numbers
	function ttc_add_to_security_blacklist( $ip )
	{
		// wordpress db info
		global $wpdb;
		global $ttc_wpdb_prefix;
		global $ip_table_name;
		
		
		// insert ip number into blacklisted ip table
		$sql = "INSERT INTO " . $ip_table_name . " ( ip ) VALUES ( '$ip' ) ";
		$result = $wpdb->query( $sql );
		
	}
	
	
	
	
	
	
	//   make sure all our tables are here, create them if not
	function ttc_security_install()
	{
		// wordpress db info
		global $wpdb;
		global $ttc_wpdb_prefix;

		
		// create our tables
		global $log_table_name;
		global $ip_table_name;
		global $agent_table_name;
		global $request_table_name;
		
		$new_table = 0;
		
		// create log table
		if($wpdb->get_var("SHOW TABLES LIKE '$log_table_name'") != $log_table_name) {
			
			$sql = "CREATE TABLE " . $log_table_name . " (
			ip varchar(16),
			problem int(3),
			accept varchar(255),
			agent varchar(255),
			request varchar(255),
			day datetime
			);";
			
			$new_table = 1;
		}
		
		// create ip table
		if( $wpdb->get_var("SHOW TABLES LIKE '$ip_table_name'") != $ip_table_name ){
			
			$sql = "CREATE TABLE ". $ip_table_name ." (
			ip varchar(255) UNIQUE
			);";
			
			$new_table = 2;
		}
		
		// create agent table
		if( $wpdb->get_var("SHOW TABLES LIKE '$agent_table_name'") != $agent_table_name ){
			
			$sql = "CREATE TABLE ". $agent_table_name ." (
			agent varchar(255) UNIQUE
			);";
			
			$new_table = 3;
		}
		
		// create request table
		if( $wpdb->get_var("SHOW TABLES LIKE '$request_table_name'") != $request_table_name ){
			
			$sql = "CREATE TABLE ". $request_table_name ." (
			request varchar(255) UNIQUE
			);";
			
			$new_table = 4;
		}
		
		// if we created any new tables update database
		if ( $new_table ){
			require_once(ABSPATH . 'wp-admin/upgrade-functions.php');
			dbDelta($sql);
		}
		
		//insert some default values to get user started
		if( $new_table == 3 ){
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'AnotherBot' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'WebRipper' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'Winnie Poh' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'EmailSearch' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'curl' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'DataCha0s' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'HTTrack' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'libcurl' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'libwww-perl' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'PEAR' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'PECL' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'Security Kol' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'Site Sniper' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'Wget' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'botpaidtoclick' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'Click Bot' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'EmailSiphon' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'GrubNG' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'lwp-request' )";
			$result = mysql_query( $sql ); 
			$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( 'lwp-trivial' )";
			$result = mysql_query( $sql ); 
			
		}
		
		if ( $new_table == 4 ){
			$sql = "INSERT INTO " . $request_table_name . " ( request ) VALUES ( '.txt?' )";
			$result = mysql_query ( $sql );
			$sql = "INSERT INTO " . $request_table_name . " ( request ) VALUES ( '.gif?' )";
			$result = mysql_query ( $sql );
			$sql = "INSERT INTO " . $request_table_name . " ( request ) VALUES ( '.jpg?' )";
			$result = mysql_query ( $sql );
			$sql = "INSERT INTO " . $request_table_name . " ( request ) VALUES ( '.xml?' )";
			$result = mysql_query ( $sql );
			$sql = "INSERT INTO " . $request_table_name . " ( request ) VALUES ( 'UPDATE' )";
			$result = mysql_query ( $sql );
		}
	}
	
	
	
	
	//  -----  user page ------------
	function ttc_security_add_menu_page()
	{
		add_options_page( 'Security logs', 'Security logs', 'manage_options', 'SecurityLogs', 'ttc_add_user_security_menu');
	}
	
	
	function ttc_add_user_security_menu()
	{

		
		if (!current_user_can('manage_options'))  {
			wp_die( __('You do not have sufficient permissions to access this page.') );
		}
		
		// wordpress db info
		global $wpdb;
		global $ttc_wpdb_prefix;

		
		if (!current_user_can('manage_options'))  {
			wp_die( __('You do not have sufficient permissions to access this page.') );
		}
		
		// our table info
		global $log_table_name;
		global $ip_table_name;
		global $agent_table_name;
		global $request_table_name;
		
		//print logs
		// how many log entries do we want?
		print "<table<tr><td>";
		print "<form method=\"post\">";
		print "Number of log entries to view: ";
		print "</td><td><input type=\"text\" name=\"log_lines\" maxlength=\"4\" size=\"4\">";
		print "</td><td><input type=\"submit\" value=\"Show Entries\">";
		print "<td><input type=\"hidden\" name=\"submit_check\" value=\"1\"></td>";
		print "</form>";
		print "</td></tr></table>";
		
		// fetch most recent lines
		$log_count = 25;
		
		if ( $_POST['submit_check'] == 1 ){
			$log_count = $_POST['log_lines'];
		}
		
		
		// create tables if they don't already exist
		if($wpdb->get_var("SHOW TABLES LIKE '$blacklist_table_name'") != $blacklist_table_name ) {
			ttc_security_install();
		}
		if($wpdb->get_var("SHOW TABLES LIKE '$ip_table_name'") != $ip_table_name ) {
			ttc_security_install();
		}
		if($wpdb->get_var("SHOW TABLES LIKE '$agent_table_name'") != $agent_table_name ) {
			ttc_security_install();
		}		
		if($wpdb->get_var("SHOW TABLES LIKE '$request_table_name'") != $request_table_name ) {
			ttc_security_install();
		}
		
		// clean out logs and remove entries older than 8 days
		$sql = "DELETE FROM $log_table_name WHERE day < (CURRENT_DATE - INTERVAL 8 DAY )";
		$deleted = $wpdb->get_results ( $sql );
		
		//fetch log information
		$sql = "SELECT ip, problem, accept, agent, request, date_format( day, '%M %d %Y %H:%i:%s') AS time_stamp FROM $log_table_name ORDER BY day DESC LIMIT $log_count";
		$log = (array)$wpdb->get_results ( $sql );
		
		
		// print log files to the admin
	    print "<br>Most recent log entries<br>";
		
		
		foreach ( $log as $log_entry ){
			
			$code = "";
			
			if( $log_entry->problem == 1){
				$code = "On our ip blacklist";
			}else if ( $log_entry->problem == 2 ){
				$code = "<font color=\"blue\">On our user agent blacklist</font>";
			}else if ( $log_entry->problem == 3 ){
				$code = "<font color=\"blue\">User agent field is blank</font>";
			}else if ( $log_entry->problem == 11 ){
				$code = "<font color=\"red\">Spamhaus listed spammer</font>";
			}else if ( $log_entry->problem == 12 ){
				$code = "<font color=\"red\">Spamhaus listed exploiter</font>";
			}else if ( $log_entry->problem == 13 ){
				$code = "<font color=\"red\">Attempted POST</font>";
			}else if ( $log_entry->problem == 14 ){
				$code = "<font color=\"red\">Attempted hack</font>";
			}
			
			
			print "<br>IP: <font color=\"olive\">$log_entry->ip</font>";
			print "&nbsp; &nbsp; &nbsp; <font color=\"green\">$log_entry->time_stamp</font>";
			print "<br>Request: <font color\"blue\">$log_entry->request</font>";
			print "<br>Code: <font color=\"teal\">$code</font>";
			print "<br>Accept: <font color=\"green\">$log_entry->accept</font>";
			print "<br>Agent: <font color=\"navy\">$log_entry->agent</font>";
			
			print "<br><hr>";
			
		}
		
		
		
		print "\n<table border=\"6\" width=\"800\"><tr><td>";
		
		// print the ip black list for editing and review to admin
		if( $ipblacklist = $_POST['ipblacklist'] ){
			$wpdb->query ( "DELETE FROM $ip_table_name WHERE 1=1" );
			$ipblacklist = explode( "\n", $ipblacklist );
			
			foreach ( $ipblacklist as $ip ){
				$ip = trim ( $ip );
				if( $ip != "" ){
					$sql = "INSERT INTO " . $ip_table_name . " ( ip ) VALUES ( '$ip' ) ";
					$wpdb->query ( $sql );
				}
			}
		}
		
		print "<form method=\"post\">";
		print "\n<table border=\"1\"><tr><td>This is your ip banished list:  <br />Add or remove ips as you wish <br /> One per line</td></tr>";
		print "<tr><td><textarea name='ipblacklist' cols='20' rows='20' >";
		
		$sql = "SELECT ip FROM $ip_table_name ORDER BY ip";
		$blacklisted_ips = (array)$wpdb->get_results( $sql );
		
		foreach( $blacklisted_ips as $ips ){
			echo  $ips->ip . "\n";
		}
		
		print "\n</textarea></td></tr></table>";
		
		print "<input type=\"submit\" name=\"ttc_ip_blacklist_update\" value=\"Update IP blacklist\">";
		print "</form>";
		
		print "</td><td>";
		
		// print the agent black list for editing and review to admin
		if( $agentblacklist = $_POST['agentblacklist'] ){
			$wpdb->query ( "DELETE FROM $agent_table_name WHERE 1=1" );
			$agentblacklist = explode( "\n", $agentblacklist );
			
			foreach ( $agentblacklist as $agent ){
				$agent = trim ( $agent );
				if( $agent != "" ){
					$sql = "INSERT INTO " . $agent_table_name . " ( agent ) VALUES ( '$agent' ) ";
					$wpdb->query ( $sql );
				}
			}
		}
		
		
		
		print "<form method=\"post\">";
		print "\n<table border=\"1\"><tr><td>This is your agent banished list:  <br />Add or remove agents as you wish <br /> One per line</td></tr>";
		print "<tr><td><textarea name='agentblacklist' cols='30' rows='20' >";
		
		$sql = "SELECT agent FROM $agent_table_name ORDER BY agent";
		$blacklisted_agents = (array)$wpdb->get_results( $sql );
		
		foreach( $blacklisted_agents as $agents ){
			echo  $agents->agent . "\n";
		}
		
		print "\n</textarea></td></tr></table>";
		
		print "<input type=\"submit\" name=\"ttc_agent_blacklist_update\" value=\"Update agent blacklist\">";
		print "</form>";		
		print "</td><td>";
		
		
		
		// print the request black list for editing and review to admin
		if( $requestblacklist = $_POST['requestblacklist'] ){
			$wpdb->query ( "DELETE FROM $request_table_name WHERE 1=1" );
			$requestblacklist = explode( "\n", $requestblacklist );
			
			foreach ( $requestblacklist as $request ){
				$request = trim ( $request );
				if( $request != "" ){
					$sql = "INSERT INTO " . $request_table_name . " ( request ) VALUES ( '$request' ) ";
					$wpdb->query ( $sql );
				}
			}
		}
		
		
		print "<form method=\"post\">";
		print "\n<table border=\"1\"><tr><td>This is your request blacklist:  <br />Add or remove requests as you wish <br /> One per line</td></tr>";
		print "<tr><td><textarea name='requestblacklist' cols='30' rows='20' >";
		
		$sql = "SELECT request FROM $request_table_name ORDER BY request";
		$blacklisted_requests = (array)$wpdb->get_results( $sql );
		
		foreach( $blacklisted_requests as $requests ){
			echo  $requests->request . "\n";
		}
		
		print "</textarea></td></tr></table>";
		
		print "<input type=\"submit\" name=\"ttc_request_blacklist_update\" value=\"Update request blacklist\">";
		print "</form>";
		print "\n</td></tr></table>";
		print "\n</td></tr></table>";
		print "\n<br> Be sure to occasionally check <a href=\"http://herselfswebtools.com/2008/06/bots-im-blocking.html\">Bots I'm blocking to update your list</a>";
		print "\n<br> And check <a href=\"http://herselfswebtools.com/2008/06/requests-im-blocking.html\">Requests I'm blocking to keep your list up to date</a>";
	}
	
	
	
	add_action( 'admin_menu', 'ttc_security_add_menu_page' );   //add admin menu for user interaction
	add_action( "init", 'ttc_security' );						// run when wordpress is run
	
	?>