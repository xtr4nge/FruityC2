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

// ----------------
// CHAT
// ----------------
var ESC_MAP = {
	'&': '&amp;',
	'<': '&lt;',
	'>': '&gt;',
	'"': '&quot;',
	"'": '&#39;'
};

function escapeHTML(s, forAttribute) {
	return s.replace(forAttribute ? /[&<>'"]/g : /[&<>]/g, function(c) {
		return ESC_MAP[c];
	});
}

function check_username() {
	if (username == "") {
		$('#mUsername').modal('show');
	}
}

function set_username() {
	username = $("#username").val();
	//username = escapeHTML(username, true);
	username = username.replace(/[^a-zA-Z0-9_\-]/g,'');
	username = username.substring(0,20);
	$("#chat-user").val(username);
}

function load_chat() {
	$("#container_chat").empty();
	$.getJSON(FruityC2+"/chat", function(obj) {
		if (typeof obj !== 'undefined' && obj.length > 0) {
			obj = obj.reverse();
			latest_cid = obj[0].id;
			$.each(obj, function(key, value) {
				content = "["+value.id+"] " + value.user + ": " + value.msg + "<br>";
				$("#container_chat").append(content);
				//latest_cid = value.id;
			});
		}
	});
}

function load_chat_msg(cid) {
	$.getJSON(FruityC2+"/chat/msg/"+cid, function(obj) {
		if (typeof obj !== 'undefined' && obj.length > 0) {
			//$("#container_chat").empty()
			obj = obj.reverse();
			latest_cid = obj[0].id;
			$.each(obj, function(key, value) {
				v_user = value.user;
				console.log($("#chat-user").val());
				if (v_user == $("#chat-user").val()) {
					v_user = "<span style='color: green'>" + v_user + "</span>";
				}
				content = "["+value.id+"] " + v_user + ": " + value.msg + "<br>";
				$("#container_chat").prepend(content);
				//latest_cid = value.id;
			});
		}
	});
}

function post_chat() {
	user = $("#chat-user").val();
	msg = $("#chat-msg").val();
	
	$.post( FruityC2+"/chat/msg", { user: user, msg: msg } );
	$("#chat-msg").val("");
	setTimeout(load_chat_msg(latest_cid), 3000);
}

function count_chat_msg(cid) {
	$.getJSON(FruityC2+"/chat/msg/"+cid, function(obj) {
		counter = 0;
		if (typeof obj !== 'undefined' && obj.length > 0) {
			$.each(obj, function(key, value) {
				counter += 1;
			});
		}
		$("#alert-chat").html(counter);
	});
}

