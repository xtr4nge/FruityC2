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

/* PAYLOADS */
function payload_add() {
    name = $("#add-payload-name").val();
    payload = $("#add-payload-payload").val();
	
	$.post( FruityC2+"/payload/add", { name: name, payload: payload } );
}

function payload_update() {
	id = $("#payload-id").val();
    name = $("#payload-name").val();
    payload = $("#payload-payload").val();
	
	$.post( FruityC2+"/payload/update", { id: id, name: name, payload: payload } );
}

function load_payload() {
    $("#container_payload").empty();
    
	content = "<div>";
	content += "<div style='display: inline-block; width: 20px;'></div>";
	content += "<div style='display: inline-block; width: 30px;'></div>";
	//content += "<div style='display: inline-block; width: 100px; font-weight: bold;'>ID</div>";
	content += "<div style='display: inline-block; width: 200px; font-weight: bold;'>Name</div>";
	//content += "<div style='display: inline-block; width: 100px; font-weight: bold;'>Payload</div>";
	content += "</div>";
	
	$("#container_payload").append(content);
	
	$.getJSON(FruityC2+"/payload", function(obj) {
        $.each(obj, function(key, value) {
			content = "<div id='payload_"+key+"'>";
			content += "<div style='display: inline-block; width: 20px;'><i class='fa fa-close' style='font-size:12px' onclick='payload_del("+key+")'></i></div>";
			content += "<div style='display: inline-block; width: 30px;'><i class='fa fa-cog' style='font-size:12px' data-toggle='modal' data-target='#mPayload' onclick='payload_load("+key+")'></i></div>";
			//content += "<div style='display: inline-block; width: 100px;'>"+key+"</div>";
			content += "<div style='display: inline-block; width: 200px;'>"+value.name+"</div>";
			//content += "<div style='display: inline-block; w-idth: 100px;'><a data-toggle='modal' data-target='#mPayload' onclick='payload_load("+key+")'>view</a></div>";
			content += "</div>";
			
			$("#container_payload").append(content);
        });
    });
}

function payload_load(id) {
	if (id > 0) {
		$.getJSON(FruityC2+"/payload?id="+id, function(obj) {
			$("#payload-id").val(id);
			$("#payload-name").val(obj.name);
			$("#payload-payload").val(Base64.decode(obj.payload));
		});
	}
}

function payload_del(id) {
	if(confirm("Delete Payload?")) {
		$.get(FruityC2+"/payload/del", 'id=' + id, function(data) {});
		$("#payload_"+id).remove();
	} else {
		return false;
	}
}

function payload_listener_load() {
	$.getJSON(FruityC2+"/listener", function(obj) {
		$("#generate-code-listener").children().remove().end();
		$.each(obj, function(key, value) {
            if (value.name != "FruityC2") {
                $("#generate-code-listener").append("<option value='"+key+"'>" + value.name + "</option>");
            }
		});
	});
}

function generate_code() {
	payload_listener = $("#generate-code-listener").val();
    payload_type = $("#generate-code-type").val();
	if (payload_type != "-") {
		$.getJSON(FruityC2+"/generate/" + payload_listener + '/' + payload_type, function(data) {
			$("#generate-code-payload").val(Base64.decode(data));
		});
	}
}

function generate_code_proxy() {
	payload_port = $("#generate-code-proxy-port").val();
    payload_type = $("#generate-code-proxy-type").val();
	if (payload_type != "-") {
		$.getJSON(FruityC2+"/generate/proxy/" + payload_port + '/' + payload_type, function(data) {
			$("#generate-code-proxy-payload").val(Base64.decode(data));
		});
	}
}

// POWERSHELL ENCODED COMMAND
function generate_encoded() {
    code = $("#generate-code-encoder-code").val();
    code = Base64.encode(code);
    code = code.replace("+","-");
    code = code.replace("/","_");

	if (code !== "") {
		$.getJSON(FruityC2+"/generate/encoder" + '/' + code, function(data) {
			$("#generate-code-encoder-encoded").val(Base64.decode(data));
		});
	}
}

function load_payload_file() {
    $("#container_payload_file").empty();
    
	content = "<div>";
	content += "<div style='display: inline-block; width: 20px;'></div>";
	content += "<div style='display: inline-block; width: 30px;'></div>";
	content += "<div style='display: inline-block; width: 200px; font-weight: bold;'>Name</div>";
	content += "</div>";
	
	$("#container_payload_file").append(content);
	
	$.getJSON(FruityC2+"/payload_file", function(obj) {
        $.each(obj, function(key, value) {
			content = "<div id='payload_file_"+key+"'>";
			content += "<div style='display: inline-block; width: 20px;'><i class='fa fa-close' style='font-size:12px' onclick='payload_file_del("+key+", \""+value+"\")'></i></div>";
			content += "<div style='display: inline-block; width: 30px;'><i class='fa fa-cog' style='font-size:12px' data-toggle='modal' data-target='#mPayload' onclick='payload_load("+key+")'></i></div>";
			content += "<div style='display: inline-block; width: 200px;'>"+value+"</div>";
			content += "</div>";
			
			$("#container_payload_file").append(content);
        });
    });
}

function payload_upload() {
    alert("to be implemented...");
}

function payload_file_del(id, name) {
	if(confirm("Delete Payload?")) {
		$.get(FruityC2+"/payload_file/del", 'name=' + name, function(data) {});
		$("#payload_file_"+id).remove();
	} else {
		return false;
	}
}

//Program a custom submit function for the form
$("form#dataUpload").submit(function(event){
 
  //disable the default form submission
  event.preventDefault();
 
  //grab all form data  
  var formData = new FormData($(this)[0]);
 
  $.ajax({
    url: FruityC2+"/payload/upload",
    type: "POST",
    data: formData,
    async: false,
    cache: false,
    contentType: false,
    processData: false,
    success: function (returndata) {
      load_payload_file();
      modal_close('mPayloadUpload');
    }
  });
 
  return false;
});
