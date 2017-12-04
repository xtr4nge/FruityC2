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

function target_exit(target) {
	if(confirm("Exit target?")) {
		$.get(FruityC2+"/target_exit", 't=' + target, function(data) {});
		$("#"+target).remove();
	} else {
		return false;
	}
}

function load() {
    $.get(FruityC2+"/target", {count: "1"},           
     function(data) {
      alert("Data Loaded: " + data);
    });
}

function load_targets() {
	view_mode = "node";
	$.getJSON(FruityC2+"/target", function(obj) {
		$("#container_target").empty();
		$("#target").empty();
		
        $.each(obj, function(key, value) {	
			os_version = value.os_version.toLowerCase();
			
			if (os_version.search("windows 7") != -1) {
				os_version = "Win7";
			} else if (os_version.search("windows 8.1") != -1) {
				os_version = "Win8.1";
			} else if (os_version.search("windows 8") != -1) {
			   os_version = "Win8";
			} else if (os_version.search("windows 10") != -1) {
			   os_version = "Win10";
			} else if (os_version.search("windows xp") != -1) {
			   os_version = "WinXP";
			} else if (os_version.search("windows server") != -1) {
			   os_version = "WinSrv";
			} else if (os_version.search("linux") != -1) {
			   os_version = "Linux";
			} else {
			   os_version = "Win";
			}
		   
			if (value.level == "3") {
				mlevel = "mLevel3Font";
			} else if (value.level == "4") {
				mlevel = "mLevel4Font";
			} else {
				mlevel = "";
			}
			
			user = value.user;
			user_name = user.split("\\")[1];
			user_domain = user.split("\\")[0];
			
			var ts = Math.floor(Date.now()/1000); // You can also use new Date().getTime()/1000 but this one is faster
			if (value.checkin < (ts - value.sleep)) {
				offline = "boff";
			} else {
				offline = "";
			}

			content = "<div id='"+key+"' class='target "+mlevel+" "+offline+"' title='"+key+"' onclick=\"set_target('"+key+"')\">";
			content += "<div style='float:left;'  t-itle='"+value.name+"'>"+os_version+"</div>";
			content += "<div style='float:right;' onclick='target_exit("+key+")'>x</div>";
			content += "<br><br>";
			content += "<div title='"+value.user+"'>"+user_name+"</div>";
			content += value.name + "<br>";
			content += value.ip;
			content += "</div>";
			
            if (key == current_tid) {
                $("#target").append("<option selected>" + key + "</option>");
            } else {
                $("#target").append("<option>" + key + "</option>");
            }
            
			$("#container_target").append(content);
        });
    });
}
//load_targets()

function load_targets_list() {
	view_mode = "list";
	$.getJSON(FruityC2+"/target", function(obj) {
		$("#container_target").empty();
		$("#target").empty();
		
		content = "<div class='view_list'>";
		content += "<div style='display: inline-block; width: 10px; margin-left: 5px;'></div>";
		content += "<div style='display: inline-block; width: 20px;'></div>";
		//content += "<div style='display: inline-block; width: 22px;'></div>";
		content += "<div style='display: inline-block; width: 20px;'></div>";
		content += "<div style='display: inline-block; width: 80px; padding-left: 10px;'>OS</div>";
		content += "<div style='display: inline-block; width: 120px;'>external</div>";
		content += "<div style='display: inline-block; width: 120px;'>internal</div>";
		content += "<div style='display: inline-block; width: 100px;'>user</div>";
		content += "<div style='display: inline-block; width: 150px;'>computer</div>";
		content += "<div style='display: inline-block; width: 50px;'>last</div>";
		content += "</div>";
		
		$("#container_target").append(content);
		
        $.each(obj, function(key, value) {			
			os_version = value.os_version.toLowerCase();
			
			if (os_version.search("windows 7") != -1) {
				os_version = "Win7";
			} else if (os_version.search("windows 8.1") != -1) {
				os_version = "Win8.1";
			} else if (os_version.search("windows 8") != -1) {
			   os_version = "Win8";
			} else if (os_version.search("windows 10") != -1) {
			   os_version = "Win10";
			} else if (os_version.search("windows xp") != -1) {
			   os_version = "WinXP";
			} else if (os_version.search("windows server") != -1) {
			   os_version = "WinSrv";
			} else if (os_version.search("linux") != -1) {
			   os_version = "Linux";
			} else {
			   os_version = "Win";
			}
		   
			if (value.level == "3") {
				mlevel = "mLevel3Font";
			} else if (value.level == "4") {
				mlevel = "mLevel4Font";
			} else {
				mlevel = "";
			}
			
			user = value.user;
			if (user.search("\\\\") != -1) {
				user_name = user.split("\\")[1];
				user_domain = user.split("\\")[0];
			} else {
				user_name = user;
			}
			
			// CHECK IF TARGET/AGENT IS OFFLINE
			var ts = Math.floor(Date.now()/1000);
			
			//console.log(value.mode);
			if (value.mode == "passive") {
				target_icon = "<i class='fa fa-link "+mlevel+"' s-tyle='font-size:12px;'></i>";
			} else if (value.checkin < (ts - value.sleep)) {
				offline = "boff";
				//target_icon = "<span class='fa-stack fa-0x' style='margin-top: -10px; margin-left: -6px; height: 20px'><i class='fa fa-desktop fa-stack-1x "+mlevel+" "+offline+"'></i><i class='fa fa-exclamation-triangle fa-stack-1x text-danger' style='font-size:14px; margin-top: -2px'></i></span>";
				target_icon = "<i class='fa fa-low-vision "+mlevel+" "+offline+"' s-tyle='font-size:12px;'></i>";
			} else {
				offline = "";
				target_icon = "<i class='fa fa-desktop "+mlevel+" "+offline+"' s-tyle='font-size:12px;'></i>";
			}

			//v_data = new Date(value.checkin * 1e3).toTimeString().split(' ')[0];
			v_data = unixtimeConverter(value.checkin);
			v_last = ts - value.checkin;
			if (v_last <=60) {
				v_last = v_last+"s";
			} else {
				v_last = (Math.round(v_last/60))+"m";
			}
			
			content = "<div id='"+key+"' class='view_list "+mlevel+"' title='"+key+"' onclick=\"set_target('"+key+"')\">";
			content += "<div style='display: inline-block; width: 10px; margin-left: 5px'><i id='inuse_"+key+"' class=''></i></div>";
			content += "<div style='display: inline-block; width: 18px;' onclick='target_exit("+key+")'><i class='fa fa-remove "+mlevel+"' style='font-size:12px;'></i></div>";
			//content += "<div style='display: inline-block; width: 20px;' onclick='target_exit("+key+")'><i class='fa fa-info "+mlevel+"' style='font-size:12px;'></i></div>";
			//content += "<div style='display: inline-block; width: 22px;'><input type='checkbox'></div>";
			content += "<div style='display: inline-block; width: 20px; '>"+target_icon+"</div>";
			content += "<div style='display: inline-block; width: 80px; padding-left: 10px;'>"+os_version+"</div>";
			content += "<div style='display: inline-block; width: 120px;'>0.0.0.0</div>";
			content += "<div style='display: inline-block; width: 120px;'>"+value.ip+"</div>";
			content += "<div style='display: inline-block; width: 100px;'>"+user_name+"</div>";
			content += "<div style='display: inline-block; width: 150px;'>"+value.name+"</div>";
			content += "<div style='display: inline-block; width: 50px;'>"+v_last+"</div>";
			content += "</div>";
			
            if (key == current_tid) {
                $("#target").append("<option selected>" + key + "</option>");
            } else {
                $("#target").append("<option>" + key + "</option>");
            }
			$("#container_target").append(content);
			
			$("#inuse_"+current_tid).addClass( "fa fa-angle-right" );
        });
    });
}
 
function check_target_log(target) {	
    $.get(FruityC2+"/log/"+target, {count: "1"},           
     function(data) {
        if (data.length != current_tid_log) {
            current_tid_log = data.length;
            $('#logs').val(data);
            $('#logs').scrollTop($('#logs')[0].scrollHeight);
        }
        
    });
}

function set_target(target) {
	$('#target').val(target).trigger('change');
	
	$("#inuse_"+current_tid).removeClass( "fa fa-angle-right" );
	$("#inuse_"+target).addClass( "fa fa-angle-right" );
	
	current_tid = target;
    //check_target_log(current_tid)
	$.get(FruityC2+"/log/"+target, {count: "1"},           
     function(data) {
      current_tid_log = data.length;
	  $('#logs').val(data);
	  $('#logs').scrollTop($('#logs')[0].scrollHeight);
    });
    
    //check_target_log(target)
	set_target_tab();
	$("#control").focus();
}

function set_control() {
    target = $("#target").val();
    data = $("#control").val();
	
	if (target !== "") {
		if (availableTags.indexOf(data) == -1) {
			//availableTags.push(data)
			availableTags.unshift(data);
		}
		
		/*
		if (availableTags[0] !== data) {
			//availableTags.unshift(data);
		}
		
		availableTags.forEach(function(element) {
			console.log("loop: " + element);
		});
		*/
	
		$.get(FruityC2+"/control", 'v=' + data + "&t=" + target, function(data) {});
		
		$("#control").val("");
	} else {
		alert("No Target Selected");
	}
}

function set_control_param(data) {
    target = $("#target").val();
    $.get(FruityC2+"/control", 'v=' + data + "&t=" + target, function(data) {});
}

// AUTOCOMPLETE COMMAND
$( function() {
    $( "#control" ).autocomplete({
      source: availableTags
    });
} );


// TARGETS
function count_target() {
	$.getJSON(FruityC2+"/target", function(obj) {
		counter = 0;
        $.each(obj, function(key, value) {
            latest_tid = obj[0];
            counter += 1;
        });
		$("#alert-target").html(counter);
    });
}

function load_view_mode() {
	if (view_mode == "node") {
		load_targets();
	} else {
		load_targets_list();
	}
}

function set_command_info(value) {
	$("#control").val(value);
	modal_close("mCommand");
}

function set_usemodule(value) {
	$("#control").val(value);
	modal_close("mModules");
}

function load_modules() {
	$("#modules_list").html("");
	$.getJSON(FruityC2+"/modules", function(obj) {
		$.each(obj, function(key, value) {
			//value = value.replace(/[\n\r]/g, '');
			//content = "<div><i class='fa fa-angle-right' s-tyle='font-size:12px;'></i> "+value+"</div>";
			content = "<div>";
			//content += "<i class='fa fa-angle-right' s-tyle='font-size:12px;'></i> ";
			content += "<i class='fa fa-upload' style='margin-right: 4px;' onclick=\"set_control_param('powershell-import "+value+"')\" title='import-module'></i> ";
			content += "<a href='#' onclick=\"set_usemodule('usemodule "+value+"')\" title='usemodule'>";
			content += value;
			content += "</a>";
			content += "</div>";
			$("#modules_list").append(content);
        });
	});
}

function set_target_tab() {
	tab = "tab-control";
	$('.nav-tabs a[href="#'+tab+'"]').tab('show');
}