var map = L.map("map_canvas", { fullscreenControl: true, fullscreenControlOptions: { position: "topleft" } });
var centre = L.latLng({{ latitude }}, {{ longitude }});
map.setView(centre, 8);
url = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";
var layer = new L.TileLayer(url, {});
map.addLayer(layer);
var bounds = L.latLngBounds(centre);
var oms = new OverlappingMarkerSpiderfier (map,{keepSpiderfied:true});
var popup = new L.Popup({closeButton:false, offset:new L.Point(0.5,-24)});
oms.addListener("click", function(marker) {
   popup.setContent(marker.alt);
   popup.setLatLng(marker.getLatLng());
   map.openPopup(popup);
});
oms.addListener("spiderfy", function(markers) {
   map.closePopup();
});
{% for _, vpn in vpns -%}
  {% if vpn.get('sessions') -%}
    bounds.extend(centre);
    {% for _, session in vpn.get('sessions').items() if session.get('local_ip') -%}
      {% if session.get('latitude') and session.get('longitude') -%}
        var latlng = new L.latLng({{ session.get('latitude') }}, {{ session.get('longitude') }});
bounds.extend(latlng);
var client_marker = L.marker(latlng).addTo(map);
oms.addMarker(client_marker);
var client_popup = L.popup().setLatLng(latlng);
client_popup.setContent("{{ session.get('username') }} - {{ session.get('remote_ip') }}");
client_marker.bindPopup(client_popup);
map.fitBounds(bounds)
      {% endif -%}
    {% endfor -%}
  {% endif -%}
{% endfor -%}
