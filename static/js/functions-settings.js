function reload_settings() {
	$.ajax({url: FruityC2 + "/reload", 
		type: "HEAD",
		timeout:1000,
		//async: false,
	});	
}

function load_source_allowed(source) {
	
	$.getJSON(FruityC2+"/settings/source/"+source, function(obj) {
        content = "";        
        $.each(obj, function(key, value) {			
            content += value + "\n";
        });
        $("#source_"+source+"_allow").val(content);
    });
	
}

function refresh_settings() {
    reload_settings();
    load_source_allowed("control");
	load_source_allowed("agents");
}
