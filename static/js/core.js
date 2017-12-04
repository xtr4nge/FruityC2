/*
# Copyright (C) 2017 xtr4nge [_AT_] gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// -------------------
// GLOBAL VARS
// -------------------


//document.cookie = "username=x; expires=Thu, 18 Dec 2022 12:00:00 UTC; path=/";

// SERVER
FruityC2 = ""
TOKEN="32F04C2998A8A3F9EA12FA79254349BD8F5CC327"

// -> LOGIN
login_ssl  = false;
login_host = "";
login_port = "";
login_user = "";

opt_chat = true;
opt_chat_chk = 60000;
opt_alert = true;
opt_alert_chk = 30000;

access_allowed = false;

// -> AUTOCOMPLETE CONSOLE
availableTags = [];
/*
var availableTags = [
  "shell",
  "powershell",
  "pwd",
  "cd",
  "checkin",
  "hashdump",
  "mimikatz",
  "check_services",
  "upload",
  "download",
  "ls",
  "dir",
  "screenshot",
  "steal_token",
  "revtoself",
  "spn_search",
  "spn_request",
  "kerberos_ticket_dump",
  "kerberos_ticket_purge"
];
*/

/*
availableTags = [];
availableTags.push("shell");
availableTags.push("powershell");
availableTags.push("pwd");
availableTags.push("cd");
availableTags.push("checkin");
availableTags.push("hashdump");
availableTags.push("mimikatz");
availableTags.push("check_services");
availableTags.push("upload");
availableTags.push("download");
availableTags.push("ls");
availableTags.push("dir");
availableTags.push("screenshot");
availableTags.push("spn_search");
availableTags.push("spn_request");
availableTags.push("spn_dump");
availableTags.push("kerberos_ticket_dump");
*/

// -> TARGET
view_mode = "list";
latest_tid = 0;
current_tid = 0;
current_tid_log = 0;

// -> CHAT
latest_cid = 0;
username = "";

// -> ALERT
latest_aid = 0;

// -------------------
// FUNCTIONS
// -------------------

function check_login() {
	login_host = localStorage.getItem('login_host');
	login_port = localStorage.getItem('login_port');
	login_ssl  = localStorage.getItem('login_ssl');
	login_user = localStorage.getItem('login_user');
	
	$("#login_host").val(login_host);
	$("#login_port").val(login_port);
	$("#login_user").val(login_user);
	
	if (login_ssl === true || login_ssl === "true") {
		$('#login_ssl')[0].checked = true;
	} else {
		$('#login_ssl')[0].checked = false;
	}
	
	if ((login_host == "" || !login_host) || (login_port == "" || !login_port)) {
		$('#mLogin').modal('show');
	} else if ((login_user == "" || !login_user)) {
		$('#connection_error').html("Error: Username");
		$('#connection_error').show();
		$('#mLogin').modal('show');
	} else {
		username = login_user;
		/*
		$("#login_host").val(login_host);
		$("#login_port").val(login_port);
		$("#login_user").val(login_user);
		*/
		$("#chat-user").val(username);
		
		if (login_ssl === true || login_ssl === "true") { login_prefix = "https"; }
		else { login_prefix = "http"; }
		
		FruityC2 = login_prefix+"://"+login_host+":"+login_port;
		server_connectivity_check(FruityC2+'/login');
	}
}

function set_login() {
	
	username = $("#login_user").val();
	
	login_host = $("#login_host").val();
	login_port = $("#login_port").val();
	login_ssl =  $("#login_ssl").is(":checked");
	login_user = $("#login_user").val();
	
	if (login_ssl === true || login_ssl === "true") { login_prefix = "https"; }
	else { login_prefix = "http"; }
	
	FruityC2 = login_prefix+"://"+login_host+":"+login_port;
	
	localStorage.setItem('login_host',login_host);
	localStorage.setItem('login_port',login_port);
	localStorage.setItem('login_ssl',login_ssl);
	localStorage.setItem('login_user',login_user);
	/*
	$("#login_host").val(login_host);
	$("#login_port").val(login_port);
	$("#login_user").val(login_user);
	$("#chat-user").val(login_user);
	*/
	modal_close("mLogin");
	location.reload();
}

function logout() {
	localStorage.setItem('login_user','');
	username = "";
	//login_host = "";
	//login_port = "";
	login_user = "";
	
	$("#login_user").val(login_user);
	$("#chat-user").val(username);
	
}

function server_connectivity_check(FruityC2) {
	
	//$.ajax({url: FruityC2+'/profiles',
	$.ajax({url: FruityC2,
        type: "HEAD",
        timeout:1000,
        statusCode: {
            200: function (response) {
                //alert('Working!');
            },
            400: function (response) {
                //alert('Not working!');
				$('#connection_error').html("Error: Host or Port");
				$('#connection_error').show();
				$('#mLogin').modal('show');
            },
			403: function (response) {
                //alert('Not working!');
				$('#connection_error').html("Error: Source IP not allowed");
				$('#connection_error').show();
				$('#mLogin').modal('show');
            },
			404: function (response) {
                //alert('Not working!');
				$('#connection_error').html("Error: Source IP not allowed or path not found");
				$('#connection_error').show();
				$('#mLogin').modal('show');
            },
            0: function (response) {
                //alert('Not working!');
				$('#connection_error').html("Error: Host/Port or Server not available");
				$('#connection_error').show();
				$('#mLogin').modal('show');
            }              
        }
 });
}

function access_check(FruityC2) {
	//$.ajax({url: FruityC2+'/profiles',
	
	if (!$('#mLogin').hasClass('in')) {
		$.ajax({url: FruityC2, 
			type: "HEAD",
			timeout:1000,
			//async: false,
			statusCode: {
				200: function (response) {
					//alert('Working!');
					//console.log("*200-access");
					access_allowed = true;
					load_core();
				},
				400: function (response) {
					//alert('Not working!');
					console.log("*400-access");
					access_allowed = false;
				},
				403: function (response) {
					console.log("*403-access");
					access_allowed = false;
				},
				404: function (response) {
					console.log("*404-access");
					access_allowed = false;
				},
				0: function (response) {
					console.log("*0-access");
					access_allowed = false;
				}              
			},
			/*
			cache: false,
			crossDomain: true,
			xhrFields: {
				withCredentials: true
			 }
			 */
	 });
	}
}

$("#logs").change(function() {
	$('#logs').scrollTop($('#logs')[0].scrollHeight);
});

function modal_close(id) {
    $('#'+id).modal('toggle');
}

function unixtimeConverter(timestamp) {
	var date = new Date(timestamp*1000);
	var year = date.getFullYear();
	var month = ("0"+(date.getMonth()+1)).substr(-2);
	var day = ("0"+date.getDate()).substr(-2);
	var hour = ("0"+date.getHours()).substr(-2);
	var minutes = ("0"+date.getMinutes()).substr(-2);
	var seconds = ("0"+date.getSeconds()).substr(-2);

	return year+"-"+month+"-"+day+" "+hour+":"+minutes+":"+seconds;
}

function load_commands() {
	$.getJSON(FruityC2+"/commands", function(obj) {
		$.each(obj, function(key, value) {
			availableTags.push(key);
			$("#command_list").append("<div class='command-info'><a href='#'' onclick='set_command_info(\""+key+"\")'>"+key+"</a></div>" + value + "<br>");
		});
	});
}

// -------------------
// LOAD FUNCTIONS
// -------------------
$('#connection_error').hide();
check_login();

function load_core() {
	//if (FruityC2 !== "") {
	if (access_allowed === true) {

		load_profiles();
		load_payload();
		load_web_delivery();
		load_listener();
		if (opt_chat === true) { load_chat(latest_cid); }
		load_view_mode();
		if (opt_alert === true) { load_alert(latest_aid); }
		load_payload_file();
		load_commands();
	
		if (opt_chat === true) { 
			setInterval(function(){
				if ($('#mChat').is(':visible')){
					load_chat_msg(latest_cid);
					$("#alert-chat").html(0);
				} else {
					count_chat_msg(latest_cid);
				}
			}, opt_chat_chk);
		}
		
		setInterval(function(){
			if (access_allowed === true) {
				count_target();
				load_view_mode();
				check_target_log(current_tid);
			}
		}, 5000);
		
		if (opt_alert === true) { 
			setInterval(function(){
				if (access_allowed === true) {
					if ($('#mAlert').is(':visible')){
						load_alert_id(latest_aid);
						$("#alert-alert").html(0);
					} else {
						count_alert(latest_aid);
					}
				} else {
					console.log("?");
				}
			}, opt_alert_chk); //5000
		}
		
		// LOAD ALLOWED SOURCES
		//refresh_settings();
		load_source_allowed("control");
		load_source_allowed("agents");
		
	} else {
		console.log("access denied.");
	}
}

// LOAD_CORE if access allowed
access_check(FruityC2+'/login');
