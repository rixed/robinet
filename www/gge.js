// vim:sw=4 ts=4 sts=4 expandtab
/* Generic Graph Editor
 *
 * We want to be able of:
 * - viewing/editing the graph by moving vertices around
 * - editing each vertex by calling a wrapper with the vertex and a handle to its drawing group
 *   (so that it can modify it's drawing) when a vertex is selected for edition.
 * - adding/deleting vertices with gge_vertex_add(vertex)/gge_vertex_del(vertex)
 *   where vertex is an object with fields x, y, draw(svg:group), on_select(svg:group)
 * - adding/deleting edges with gge_edge_add(edge)/gge_edge_del(edge)
 *   where edge is an object with fields from, to.
 * - gge.vertices and gge.edges will be the list of vertices/edges
 */

/* Create a new graph in the given SVG */
function gge_new(svgid)
{
    var pic_scale = 1;

    // Zoom
    var gge = {
        group: d3.select("svg#"+svgid)
                 .attr("pointer-events", "all")
                 .on("mousemove", function() {
                     var pos = map(d3.svg.mouse(this), function (c) { return c/pic_scale; });
                     if (gge.dragged != null) {
                         gge.dragged.x = pos[0];
                         gge.dragged.y = pos[1];
                         gge.dragged.group_o.attr("transform", "translate("+pos[0]+","+pos[1]+")");
                         foreach(gge.dragged.edges_from, function (c) {
                             c.line.attr("x1", pos[0]);
                             c.line.attr("y1", pos[1]);
                         });
                         foreach(gge.dragged.edges_to, function (c) {
                             c.line.attr("x2", pos[0]);
                             c.line.attr("y2", pos[1]);
                         });
                     }
                 })
                 .on("mouseup", function () {
                     if (gge.dragged) {
                         gge.dragged.group_i
                             .attr("transform", "scale(1)")
                             .select("circle.gge_handle")
                             .classed("gge_dragged", false);
                         gge.dragged = null;
                     }
                 })
                 .append("svg:g")
                 .attr("transform", "scale("+pic_scale+")"),
        dragged: null,
        selected: null,
        vertices: [],
        edges: [],
    };

    // With d3.select().on("mousewheel") I didn't manage to disable browser scrolling :-\
    document.getElementById(svgid).onmousewheel = function (_e) {
        if (window.event.wheelDelta > 0) {
            pic_scale += 0.1;
        } else {
            pic_scale -= 0.1;
        }
        gge.group.attr("transform", "scale("+pic_scale+")");
        return false;
    };
 
    return gge;
}

var gge_handle_radius = 20;

function gge_vertex_add(gge, vertex)
{
    // outer group, for translation
    vertex.group_o = gge.group.append("svg:g")
        .attr("transform", "translate("+vertex.x+","+vertex.y+")");
    // inner group, for scaling
    vertex.group_i = vertex.group_o.append("svg:g")
        .classed("gge_inner", true)
        .attr("transform", "scale(1)");

    // Draw the handle
    vertex.group_i.append("circle")
        .classed("gge_handle", true)
        .attr("r", gge_handle_radius)
        .attr("cx", 0)
        .attr("cy", 0)
        .on("mousedown", function (d) {
            if (gge.dragged === null) {
                gge.dragged = vertex;
                gge.selected = vertex;
                vertex.group_i
                    .transition().duration(40)
                    .attr("transform", "scale(1.5)")
                vertex.group_i
                    .select("circle.gge_handle")
                    .classed("gge_dragged", true);
                vertex.on_select(vertex.group_i);
            }
        });
    vertex.edges_from = [];
    vertex.edges_to = [];
    vertex.draw(vertex.group_i);
    gge.vertices.push(vertex);
}

function gge_vertex_del(gge, vertex)
{
    // Remove all edges using this vertex.
    // We must copy edges_from/edges_to since gge_edge_del will alter it
    var edges_to_del = vertex.edges_from.concat(vertex.edges_to);
    foreach(edges_to_del, function (e) { gge_edge_del(gge, e); });
    // Remove from the vertices list
    array_del(gge.vertices, vertex);
    // Remove from the svg
    vertex.group_o.remove();
    /// From internal structure
    if (gge.selected == vertex) gge.selected = null;
    if (gge.dragged == vertex) gge.dragged = null;
}

function gge_edge_add(gge, edge)
{
    edge.line = gge.group.append("line")
        .classed("gge_edge", true)
        .attr("x1", edge.from.x)
        .attr("y1", edge.from.y)
        .attr("x2", edge.to.x)
        .attr("y2", edge.to.y);
    edge.from.edges_from.push(edge);
    edge.to.edges_to.push(edge);
    gge.edges.push(edge);
}

function gge_edge_del(gge, edge)
{
    // Remove from the various lists
    array_del(edge.from.edges_from, edge);
    array_del(edge.to.edges_to, edge);
    array_del(gge.edges, edge);
    // Remove from the svg
    edge.line.remove();
}

