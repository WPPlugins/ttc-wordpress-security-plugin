=== TTC WordPress Security Tool ===
Contributors: Linda MacPhee-Cobb
Tags: bots, scrapers, cross-site scripting, block agents, block ip, security
Requires at least: 2.5
Tested up to: 2.5.1
Stable tag: 2.0

This plugin blocks scrapers, cross-site scripting attempts, and other ill behaved bots.  This is the second of three security plugins. 




== Description ==
This is part 2 of a 3 part security suite for WordPress.  This part blocks cross-site script attempts, ip numbers of ill behaved people and bots and bans bad user agents.  Since trouble is always changing this plugin allows you to adjust who you want to block.  I've started you out with every bad bot I caught on my site this past month.  You can remove bots, add bots and add and remove ips and requests.

Many internet websites list bad bots, or you can just watch your access-logs to see who is causing problems on your site.  Several tools for finding weaknesses in your WP to hack are blocked and you can add more to the list as new ones appear on the net.

Cross site scripting attacks often contain .txt? .txt?? .txt??? or ?_wp_http_referer in the request.  If new cross site scripts show up, you can easily add them to the list.

Anyone who's bot or request shows up on your black list has his ip automatically added to your blacklisted ip list.

This plugin creates a page under 'Manage'. On it you can blacklist ip numbers, user agents, and requests that you don't want on your site.  

If you have the TTC User Registration Bot Detector installed, both plugins will use the same bad ip list to make things easier for you.

The management page will also give you a list of all attempts at registration and if they were bounced and why.

To block an individual ip 
255.255.255.255

to block all ips between 255.255.255.0 to 255.255.255.255
255.255.255.

to block all ips between 255.255.0.0 to 255.255.255.255
255.255.

to block all ips between 255.0.0.0 to 255.255.255.255
255.

if you do not use dots at the end then 150.12 will block 150.12.x.x , 150.120.x.x , 150.121.x.x, &t



To prevent yourself from being banned change line 118
	//else if ( $http_remote_addr == "127.0.0.1" ){ $blacklisted = 0; }  //uncomment this and add your ip to prevent self-banishment

remove the beginning //, then change 127.0.0.1 to your ip number


== Installation ==
Upload this plugin to your plugin directory and activate it.

You should also look at the two error pages returned ( line 137 & line 165 ) and customize them if you wish.

And you should uncomment and change 127.0.0.1 to your ip number and uncomment that line