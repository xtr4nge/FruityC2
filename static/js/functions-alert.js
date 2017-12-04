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

// ALERT
//latest_aid = 0
function load_alert() {
	$("#container_alert").empty();
	$.getJSON(FruityC2+"/alert", function(obj) {
		if (typeof obj !== 'undefined' && obj.length > 0) {
			obj = obj.reverse();
			latest_aid = obj[0].id;
			$.each(obj, function(key, value) {
				if (value.level == "high") {
					c_level = "danger";
				} else if (value.level == "warning") {
					c_level = "warning";
				} else if (value.level == "low") {
					c_level = "info";
				} else {
					c_level = "";
				}
				content = "[<span class='"+c_level+"'>"+value.id+"</span>] " + value.remote + ": " + value.msg + " | " + value.path +"<br>";
				$("#container_alert").append(content);
			});
		}
	});
}

function load_alert_id(aid) {
	$.getJSON(FruityC2+"/alert/"+aid, function(obj) {
		if (typeof obj !== 'undefined' && obj.length > 0) {
			//$("#container_chat").empty()
			obj = obj.reverse();
			latest_aid = obj[0].id;
			$.each(obj, function(key, value) {
				if (value.level == "high") {
					c_level = "danger";
				} else if (value.level == "warning") {
					c_level = "warning";
				} else if (value.level == "low") {
					c_level = "info";
				} else {
					c_level = "";
				}
				content = "[<span class='"+c_level+"'>"+value.id+"</span>] " + value.remote + ": " + value.msg + " | " + value.path +"<br>";
				$("#container_alert").prepend(content);
			});
		}
	});
}

function count_alert(aid) {
	$.getJSON(FruityC2+"/alert/"+aid, function(obj) {
		counter = 0;
		if (typeof obj !== 'undefined' && obj.length > 0) {
			$.each(obj, function(key, value) {
				counter += 1;
			});
		}
        if (counter > 100) {
            $("#alert-alert").html("+100");
        } else {
            $("#alert-alert").html(counter);
        }
		
	});
}
