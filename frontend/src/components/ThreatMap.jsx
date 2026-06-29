import React, { useState, useEffect } from 'react';
import { MapContainer, TileLayer, GeoJSON, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { AlertTriangle, Shield, Activity, MapPin, Globe } from 'lucide-react';
import { useSOC } from '../hooks/useSOC';
import kenyaCounties from '../data/kenya-counties.json';
import { getToken } from '../auth';

// Fix for default Leaflet marker icons in React
import icon from 'leaflet/dist/images/marker-icon.png';
import iconShadow from 'leaflet/dist/images/marker-shadow.png';
let DefaultIcon = L.icon({
    iconUrl: icon,
    shadowUrl: iconShadow,
    iconSize: [25, 41],
    iconAnchor: [12, 41]
});
L.Marker.prototype.options.icon = DefaultIcon;

const ThreatMap = () => {
  const [advisories, setAdvisories] = useState([]);
  const [wazuhAgents, setWazuhAgents] = useState([]);
  const [attackVectors, setAttackVectors] = useState([]);
  const { isDark } = useSOC();

  useEffect(() => {
    const token = getToken();
    const headers = token ? { 'Authorization': `Bearer ${token}` } : {};

    // Fetch live RSS advisories (Cybersecurity News)
    fetch('/api/feeds/advisories/', { headers })
      .then(res => res.json())
      .then(data => {
        if (data.advisories) setAdvisories(data.advisories);
      })
      .catch(err => console.error("Failed to fetch advisories", err));

    // Fetch scraped OSINT map data
    fetch('/api/map-data/', { headers })
      .then(res => res.json())
      .then(data => {
        if (data.agents) setWazuhAgents(data.agents);
        if (data.vectors) setAttackVectors(data.vectors);
      })
      .catch(err => console.error("Failed to fetch map data", err));
  }, []);

  const getFeatureStyle = (feature) => {
    const countyName = feature.properties.COUNTY || "";
    let fillColor = isDark ? '#1f2937' : '#f3f4f6';
    let fillOpacity = 0.4;
    let weight = 1;

    // Highlight targeted counties (Nairobi/Mombasa commonly attacked in generic OSINT mappings)
    if (['Nairobi', 'Mombasa', 'Kisumu'].includes(countyName)) {
      fillColor = '#ef4444'; 
      fillOpacity = 0.6;
      weight = 2;
    }

    return {
      fillColor,
      fillOpacity,
      color: isDark ? '#4b5563' : '#9ca3af',
      weight
    };
  };

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)] relative overflow-hidden bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-slate-200 dark:border-slate-800">
      
      {/* Top Overlay Stats */}
      <div className="absolute top-4 left-4 z-[400] flex gap-4">
        <div className="bg-white/90 dark:bg-slate-800/90 backdrop-blur-sm p-4 rounded-lg shadow-lg border border-slate-200 dark:border-slate-700 flex items-center gap-3">
          <div className="p-2 bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 rounded-lg">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Global Threat Vectors</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white">{attackVectors.length} Active</p>
          </div>
        </div>
        <div className="bg-white/90 dark:bg-slate-800/90 backdrop-blur-sm p-4 rounded-lg shadow-lg border border-slate-200 dark:border-slate-700 flex items-center gap-3">
          <div className="p-2 bg-red-100 dark:bg-red-900/50 text-red-600 dark:text-red-400 rounded-lg">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Targeted KE Sectors</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white">{wazuhAgents.length} Regions</p>
          </div>
        </div>
      </div>

      {/* Map Container */}
      <div className="flex-1 w-full h-full relative z-[1]">
        <MapContainer 
          center={[0.0236, 37.9062]} // Center of Kenya
          zoom={5} 
          style={{ height: '100%', width: '100%', zIndex: 1 }}
          zoomControl={true}
        >
          <TileLayer
            url={isDark 
              ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png' 
              : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'}
            attribution='&copy; <a href="https://carto.com/">CARTO</a>'
          />

          {/* Layer 1: Kenya Counties */}
          {kenyaCounties && (
            <GeoJSON 
              data={kenyaCounties} 
              style={getFeatureStyle}
              onEachFeature={(feature, layer) => {
                if (feature.properties && feature.properties.COUNTY) {
                  layer.bindTooltip(feature.properties.COUNTY, { direction: 'center', className: 'text-xs font-bold' });
                }
              }}
            />
          )}

          {/* Layer 2: Targeted Regions in Kenya */}
          {wazuhAgents.map(target => (
            <Marker key={target.id} position={target.coords}>
              <Popup className="dark:bg-slate-800 min-w-[250px]">
                <div className="p-2 max-w-xs">
                  <h3 className="font-bold text-lg mb-1">{target.name}</h3>
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${target.status === 'Critical' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'}`}>
                      {target.status}
                    </span>
                  </div>
                  <p className="text-sm font-semibold mb-1">Active Threats ({target.alerts}):</p>
                  <ul className="text-xs text-slate-500 list-disc pl-4 space-y-1 max-h-32 overflow-y-auto">
                    {target.threats && target.threats.map((t, idx) => (
                      <li key={idx}>
                        <a href={t.link} target="_blank" rel="noreferrer" className="hover:text-blue-500 hover:underline">
                          {t.title}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              </Popup>
            </Marker>
          ))}

          {/* Layer 3: Attack Vectors */}
          {attackVectors.map(vector => (
            <React.Fragment key={vector.id}>
              {/* Origin Marker */}
              <Marker position={vector.origin}>
                <Popup className="dark:bg-slate-800 min-w-[250px]">
                  <div className="p-2 max-w-xs">
                    <h3 className="font-bold text-sm text-red-600 mb-1">Threat Origin: {vector.originName}</h3>
                    <p className="text-xs text-slate-500 mt-1 font-semibold">Associated Campaign:</p>
                    <a href={vector.link} target="_blank" rel="noreferrer" className="text-xs hover:text-blue-500 hover:underline block mt-1">
                      {vector.type}
                    </a>
                  </div>
                </Popup>
              </Marker>
              
              {/* Animated Line */}
              <Polyline
                positions={[vector.origin, vector.target]}
                pathOptions={{ 
                  color: '#ef4444', 
                  weight: 2, 
                  opacity: 0.7,
                  dashArray: '10, 10',
                  className: 'animate-dash' 
                }}
              />
            </React.Fragment>
          ))}
        </MapContainer>
      </div>

      {/* Layer 4: Live Ticker Footer (News/Advisories) */}
      <div className="h-12 bg-slate-900 text-slate-300 flex items-center px-4 overflow-hidden z-[400] border-t border-slate-700 relative">
        <div className="flex-shrink-0 font-bold text-white bg-red-600 px-3 py-1 rounded text-sm mr-4 z-10 shadow-[4px_0_10px_rgba(15,23,42,1)]">
          GLOBAL CYBER THREAT NEWS
        </div>
        <div className="flex-1 overflow-hidden relative h-full">
          <div className="absolute whitespace-nowrap animate-marquee flex items-center h-full">
            {advisories.length > 0 ? advisories.map((adv, idx) => (
              <span key={idx} className="mx-8 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-500" />
                <a href={adv.link} target="_blank" rel="noreferrer" className="hover:text-white hover:underline">
                  {adv.title}
                </a>
                <span className="text-xs text-slate-500 ml-2">({new Date(adv.pubDate).toLocaleDateString()})</span>
              </span>
            )) : (
              <span className="text-slate-500 italic">Fetching latest global cybersecurity news...</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default ThreatMap;
