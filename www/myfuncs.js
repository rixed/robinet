// vim:sw=4 ts=4 sts=4 expandtab
// tools

function foreach(arr, f)
{
    for (var c = 0; c < arr.length; c++) f(arr[c]);
}

function map(arr, f)
{
    var r = [];
    foreach(arr, function (e) { r.push(f(e)); });
    return r;
}

// if object item is seen in arr, then splice arr to remove it
function array_del(arr, item)
{
    for (var i = 0; i < arr.length; i++) {
        if (arr[i] === item) {
            arr.splice(i, 1);
            i--;
        }
    }
}

function curry_1_2(f, p1)
{
    return function (p2) { return f(p1, p2); };
}

function quote(str)
{
    return '"' + str.replace('"', "\\\"") + '"';
}

//
function http_send(method, url, data, cont) {
    var http = new XMLHttpRequest();
    http.open(method, url, true);

    // Send the proper header information along with the request
    if (method == "POST") {
        http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    }

    http.onreadystatechange = function() {
        if (http.readyState == http.DONE) {
            if (cont !== null) cont(http.status == 200, http.responseText);
        }
    }
    http.send(data);
}


//
function load_menu(selected)
{
    d3.csv("menu.csv", function (rows) {
        if (null == rows) {
            alert("Cannot fetch menu.csv?");
        } else {
            d3.select("div#menu")
                .selectAll("a")
                .data(rows)
                .enter()
                .append("a")
                .attr("name", function (d) { return d.name; })
                .attr("href", function (d) { return d.href; })
                .classed("selected", function(d) { return d.name == selected; })
                .text(function (d) { return d.label; });
        }
    });
}

/* Net editor */

var link_start = null;

function may_end_link(link_stop)
{
    if (link_start === null) return may_end_unlink(link_stop);
    if (link_stop === link_start) {
        alert("Cannot link to myself!");
        return;
    }
    if (link_stop.type == "note" || link_start.type == "note") {
        alert("Cannot link notes");
    } else {
        gge_edge_add(gge, cable_new(link_start, link_stop));
    }
    d3.select("div#controls input#netlink").classed("link_started", false);
    link_start = null;
}

var unlink_start = null;

function may_end_unlink(unlink_stop)
{
    if (unlink_start === null) return;
    if (unlink_stop === unlink_start) {
        alert("Cannot unlink from myself!");
        return;
    }
    // find this edge
    var del_some = false;
    function check_edge(e, dest) {
        if (dest === unlink_stop) {
            gge_edge_del(gge, e);
            del_some = true;
        }
    }
    foreach(unlink_start.edges_from, function (e) {
        check_edge(e, e.to);
    });
    foreach(unlink_start.edges_to, function (e) {
        check_edge(e, e.from);
    });
    if (del_some) {
        d3.select("div#controls input#netunlink").classed("unlink_started", false);
        unlink_start = null;
    }
}

function new_controls()
{
    // remove previous form items
    var div = d3.selectAll("div#dyncontrols");
    div.html("");
    return div;
}

function add_button(div, label, field, updater, obj, group)
{
    div.append("label").text(label + ":")
        .append("input").attr("name", field).attr("value", obj[field])
        .on("change", function() {
            obj[field] = this.value;
            updater(obj, group);
        });
}

function update_note(note, group)
{
    group.select("text.note").text(note.name + "\n" + note.text);
}

function draw_note(note, group)
{
    group.append("text").classed("note", true);
    update_note(note, group);
}

function select_note(note, group)
{
    var div = new_controls();
    add_button(div, "Title", "name", update_note, note, group);
    var area = div.append("textarea").attr("name", "text");
    area.text(note.text)
    area.on("change", function() {
        note.text = this.value;
        update_note(note, group);
    });
    may_end_link(note);
}

function update_hub(hub, group)
{
    group.select("text.hub").text(hub.name + " (" + hub.num_ports + ")");
}

function draw_hub(hub, group)
{
    group.append("text").classed("hub", true)
        .attr("text-anchor", "middle");
    update_hub(hub, group);
}

function select_hub(hub, group)
{
    var div = new_controls();
    add_button(div, "Name", "name", update_hub, hub, group);
    add_button(div, "Num ports", "num_ports", update_hub, hub, group);
    may_end_link(hub);
}

function update_switch(sw, group)
{
    update_hub(sw, group);
}

function select_switch(sw, group)
{
    var div = new_controls();
    add_button(div, "Name", "name", update_switch, sw, group);
    add_button(div, "Num ports", "num_ports", update_switch, sw, group);
    add_button(div, "MAC table size", "num_macs", update_switch, sw, group);
    may_end_link(sw);
}

function draw_switch(sw, group)
{
    draw_hub(sw, group);
}

function update_host(host, group)
{
    group.select("text.host")
        .attr("text-anchor", "middle")
        .text(host.name);
}

function draw_host(host, group)
{
    group.append("text").classed("host", true);
    update_host(host, group);
}

function select_host(host, group)
{
    var div = new_controls();
    add_button(div, "Name", "name", update_host, host, group);
    add_button(div, "Gateway", "gw", update_host, host, group);
    add_button(div, "Name Server", "nameserver", update_host, host, group);
    add_button(div, "Search Suffix", "search_sfx", update_host, host, group);
    add_button(div, "IP", "ip", update_host, host, group);
    add_button(div, "MAC", "mac", update_host, host, group);
    may_end_link(host);
}

function cable_new(from, to) {
    return { type: "cable", from: from, to: to, save: save_cable }
}

var gge;
function load_net_editor(netname, svgid)
{
    gge = gge_new(svgid);
    gge.netname = netname;  // keep it for later

    // Populate the graph
    d3.csv("nets/"+netname+"/note.csv", function (rows) {
        foreach(rows, function (note) {
            note.draw = curry_1_2(draw_note, note);
            note.on_select = curry_1_2(select_note, note);
            note.save = save_note;
            note.type = "note";
            gge_vertex_add(gge, note);
        });
    });

    var vertices = []; // indexed by type,name for later reference by cables CSV
    var done = 0;
    d3.csv("nets/"+netname+"/hub.csv", function (rows) {
        foreach(rows, function (hub) {
            vertices["hub," + hub.name] = hub;
            hub.draw = curry_1_2(draw_hub, hub);
            hub.on_select = curry_1_2(select_hub, hub);
            hub.save = save_hub;
            hub.type = "hub";
            gge_vertex_add(gge, hub);
        });
        if (++ done == 3) set_all_edges();
    });
    d3.csv("nets/"+netname+"/switch.csv", function (rows) {
        foreach(rows, function (sw) {
            vertices["switch," + sw.name] = sw;
            sw.draw = curry_1_2(draw_switch, sw);
            sw.on_select = curry_1_2(select_switch, sw);
            sw.save = save_switch;
            sw.type = "switch";
            gge_vertex_add(gge, sw);
        });
        if (++ done == 3) set_all_edges();
    });
    d3.csv("nets/"+netname+"/host.csv", function (rows) {
        foreach(rows, function (host) {
            vertices["host," + host.name] = host;
            host.draw = curry_1_2(draw_host, host);
            host.on_select = curry_1_2(select_host, host);
            host.save = save_host;
            host.type = "host";
            gge_vertex_add(gge, host);
        });
        if (++ done == 3) set_all_edges();
    });
    
    /* Add all the edges - once the previous items are loaded! */
    function set_all_edges() {
        d3.csv("nets/"+netname+"/cable.csv", function (rows) {
            foreach(rows, function(cable) {
                var from = vertices[cable.type1 + ',' + cable.name1];
                var to   = vertices[cable.type2 + ',' + cable.name2];
                gge_edge_add(gge, cable_new(from, to));
            });
        });
    }
}

// Writing

function save_note(note)
{
    return ["note", quote(note.name), note.x, note.y, quote(note.text)];
}
function save_hub(hub)
{
    return ["hub", quote(hub.name), hub.x, hub.y, hub.num_ports];
}
function save_switch(sw)
{
    return ["switch", quote(sw.name), sw.x, sw.y, sw.num_ports, sw.num_macs];
}
function save_host(host)
{
    return ["host", quote(host.name), host.x, host.y, host.gw, host.search_sfx, host.nameserver, host.mac, host.ip];
}
function save_cable(cable)
{
    return ["cable", cable.from.type, quote(cable.from.name), cable.to.type, quote(cable.to.name)];
}

function save_net()
{
    var data = []
    foreach(gge.vertices, function (v) { data.push(v.save(v)); });
    foreach(gge.edges, function (e) { data.push(e.save(e)); });
    data = map(data, function (a) { return a.join(","); }).join("\n");

    http_send("PUT", "nets/"+gge.netname+".csv", data, function (ok, resp) {
        if (ok) {
            alert("Done");
        } else {
            alert("Fail!\n\n" + resp);
        }
    });
}

function new_net_item()
{
    var what = d3.select("div#controls form select[name=what]").property("value");

    var vertex = { x: 0, y: 0, name: "new "+what, type: what };
    switch (what) {
        case "note":
            vertex.draw = curry_1_2(draw_note, vertex);
            vertex.on_select = curry_1_2(select_note, vertex);
            vertex.save = save_note;
            vertex.text = "enter text here";
            break;
        case "hub":
            vertex.draw = curry_1_2(draw_hub, vertex);
            vertex.on_select = curry_1_2(select_hub, vertex);
            vertex.save = save_hub;
            vertex.num_ports = 8;
            break;
        case "switch":
            vertex.draw = curry_1_2(draw_switch, vertex);
            vertex.on_select = curry_1_2(select_switch, vertex);
            vertex.save = save_switch;
            vertex.num_ports = 8;
            vertex.num_macs = 512;
            break;
        case "host":
            vertex.draw = curry_1_2(draw_host, vertex);
            vertex.on_select = curry_1_2(select_host, vertex);
            vertex.save = save_host;
            vertex.gw = "";
            vertex.nameserver = "";
            vertex.search_sfx = "";
            vertex.ip = "";
            vertex.mac = "";
            break;
        default:
            alert("Don't know how to create a new "+what);
            return;
    }
    gge_vertex_add(gge, vertex);
}

function del_net_item()
{
    if (gge.selected === null) {
        alert("Select an item first");
        return;
    }

    gge_vertex_del(gge, gge.selected);
    new_controls(); // reset the item edit form
}

function new_net_link()
{
    if (gge.selected === null) {
        alert("Select an item first");
        return;
    }

    var link_button = d3.select("div#controls input#netlink");
    if (link_button.classed("link_started")) {
        link_button.classed("link_started", false);
        link_start = null;
    } else {
        link_button.classed("link_started", true);
        link_start = gge.selected;
        d3.select("div#controls input#netunlink").classed("unlink_started", false);
        unlink_start = null;
    }
}

function del_net_link()
{
    if (gge.selected === null) {
        alert("Select an item first");
        return;
    }

    var link_button = d3.select("div#controls input#netunlink");
    if (link_button.classed("unlink_started")) {
        link_button.classed("unlink_started", false);
        unlink_start = null;
    } else {
        link_button.classed("unlink_started", true);
        unlink_start = gge.selected;
        d3.select("div#controls input#netlink").classed("link_started", false);
        link_start = null;
    }
}
