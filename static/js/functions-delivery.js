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

function web_delivery_add() {
    name = $("#add-webd-name").val();
    path = $("#add-webd-path").val();
	type = $("#add-webd-type").val();
	filename = $("#add-webd-filename").val();
	payload_type = $("#add-webd-payload-type").val();
    payload_id = $("#add-webd-payload-id").val();

	$.post( FruityC2+"/web_delivery/add", { name: name, path: path, type: type, filename: filename, payload_type: payload_type, payload_id: payload_id } );
}

function web_delivery_update() {
	id = $("#web-delivery-id").val();
    name = $("#web-delivery-name").val();
    path = $("#web-delivery-path").val();
	type = $("#web-delivery-type").val();
	filename = $("#web-delivery-filename").val();
	payload_type = $("#web-delivery-payload-type").val();
    payload_id = $("#web-delivery-payload-id").val();
	
	$.post( FruityC2+"/web_delivery/update", { id: id, name: name, path: path, type: type, filename: filename, payload_type: payload_type, payload_id: payload_id } );
}

function load_web_delivery() {
	$("#container_web_delivery").empty();
    
	content = "<div>";
	content += "<div style='display: inline-block; width: 20px;'></div>";
	content += "<div style='display: inline-block; width: 30px;'></div>";
	content += "<div style='display: inline-block; width: 200px; font-weight: bold;'>Name</div>";
	content += "<div style='display: inline-block; width: 100px; font-weight: bold;'>Path</div>";
	content += "<div style='display: inline-block; width: 100px; font-weight: bold;'>Type</div>";
	content += "<div style='display: inline-block; width: 100px; font-weight: bold;'>File Name</div>";
	content += "<div style='display: inline-block; width: 100px; font-weight: bold;'>Payload ID</div>";
	content += "</div>";
	
	$("#container_web_delivery").append(content);
	
	$.getJSON(FruityC2+"/web_delivery", function(obj) {
        $.each(obj, function(key, value) {
			content = "<div  id='web_delivery_"+key+"'>";
			content += "<div style='display: inline-block; width: 20px;'><i class='fa fa-close' style='font-size:12px' onclick='web_delivery_del("+key+")'></i></div>";
			content += "<div style='display: inline-block; width: 30px;'><i class='fa fa-cog' style='font-size:12px' data-toggle='modal' data-target='#mWebDelivery' onclick='web_delivery_load("+key+")'></i></div>";
			content += "<div style='display: inline-block; width: 200px;'>"+value.name+"</div>";
			content += "<div style='display: inline-block; width: 100px;'>"+value.path+"</div>";
			content += "<div style='display: inline-block; width: 100px;'>"+value.type+"</div>";
			content += "<div style='display: inline-block; width: 100px;'>"+value.filename+"</div>";
			content += "<div style='display: inline-block; width: 100px;'>"+value.payload+"</div>";
			content += "</div>";
			
			$("#container_web_delivery").append(content);
        });
    });
}

function web_delivery_load(id) {
	if (id > 0) {
		$.getJSON(FruityC2+"/web_delivery?id="+id, function(obj) {
			console.log(obj);
			$("#web-delivery-id").val(id);
			$("#web-delivery-name").val(obj.name);
			$("#web-delivery-path").val(obj.path);
			$("#web-delivery-filename").val(obj.filename);
            
            // LOAD TYPE (string|download)
            $("#web-delivery-type").children().remove().end();
            
            var a_types = ["download", "string"];
            for (var i=0; i<a_types.length; i++){
                if (a_types[i] == obj.type) { 
                    $("#web-delivery-type").append("<option value='"+a_types[i]+"' selected>" + a_types[i] + "</option>");
                } else {
                    $("#web-delivery-type").append("<option value='"+a_types[i]+"'>" + a_types[i] + "</option>");
                }
            }
            
            // LOAD PAYLOAD TYPE (code|file)
            $("#web-delivery-payload-type").children().remove().end();
            
            var a_types = ["code", "file"];
            for (var i=0; i<a_types.length; i++){
                if (a_types[i] == obj.payload_type) { 
                    $("#web-delivery-payload-type").append("<option value='"+a_types[i]+"' selected>" + a_types[i] + "</option>");
                } else {
                    $("#web-delivery-payload-type").append("<option value='"+a_types[i]+"'>" + a_types[i] + "</option>");
                }
            }
            
            // LOAD PAYLODS > PULLDOWN
            if (obj.payload_type == "file") {
                web_delivery_payload_file_load(obj.payload);
            } else {
                web_delivery_payload_load(obj.payload);
            }
		});
	}
}

function web_delivery_payload_load(payload) {
	$.getJSON(FruityC2+"/payload", function(obj) {
		$("#web-delivery-payload-id").children().remove().end();
		$("#add-webd-payload-id").children().remove().end();
		$.each(obj, function(key, value) {
            if (payload == key) {
                $("#web-delivery-payload-id").append("<option value='"+key+"' selected>" + value.name + "</option>");
            } else {
    			$("#web-delivery-payload-id").append("<option value='"+key+"'>" + value.name + "</option>");
            }
            $("#add-webd-payload-id").append("<option value='"+key+"'>" + value.name + "</option>");
		});
	});
}

function web_delivery_payload_file_load(payload) {
	$.getJSON(FruityC2+"/payload_file", function(obj) {
		$("#web-delivery-payload-id").children().remove().end();
		$("#add-webd-payload-id").children().remove().end();
		$.each(obj, function(key, value) {
            if (payload == value) {
                $("#web-delivery-payload-id").append("<option value='"+value+"' selected>" + value + "</option>");
            } else {
    			$("#web-delivery-payload-id").append("<option value='"+value+"'>" + value + "</option>");
            }
            $("#add-webd-payload-id").append("<option value='"+value+"'>" + value + "</option>");
		});
	});
}

function web_delivery_del(id) {
	if(confirm("Delete Web Delivery?")) {
		$.get(FruityC2+"/web_delivery/del", 'id=' + id, function(data) {});
		$("#web_delivery_"+id).remove();
	} else {
		return false;
	}
}

function load_payload_options(obj) {
    if ($("#"+obj.id).val() == "file") {
        web_delivery_payload_file_load("");
    } else {
        web_delivery_payload_load("");
    }
}