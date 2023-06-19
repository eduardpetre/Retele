import plotly.graph_objects as plot

# lista cu coordonatele locatiilor 
locations = ['44.4323,26.1063', '48.2085,16.3721', '48.2085,16.3721', '47.6740,-122.1215', '50.1155,8.6842', '50.1155,8.6842', '50.1155,8.6842', '50.1006,8.7665', '22.2783,114.1747', '47.6740,-122.1215', '47.6740,-122.1215', '-37.8140,144.9633', '-33.8678,151.2073']

# cod preluat de pe net modificat
# pentru fiecare pereche de locatii (i, i+1) construieste drumul parcurs de pachet si face plot peste o harta
# construieste un meniu pentru a vedea fiecare hop in parte si fiecare locatie prin care trece 
map = plot.Figure()
for i in range(len(locations) - 1):
    lat1, lon1 = locations[i].split(",")
    lat2, lon2 = locations[i + 1].split(",")
    
    map.add_trace(plot.Scattermapbox(
        name=f'Locatia {i+1}',
        text=f'Locatia {i+1}',
        mode="markers",
        lon=[float(lon1)],
        lat=[float(lat1)],
        marker={'size': 10}
    ))

    map.add_trace(plot.Scattermapbox(
        name=f'Locatia {i+2}',
        text=f'Locatia {i+2}',
        mode="markers",
        lon=[float(lon2)],
        lat=[float(lat2)],
        marker={'size': 10}
    ))

    map.add_trace(plot.Scattermapbox(
        name=f'Ruta dintre locatia {i+1} - locatia {i+2}',
        mode="lines",
        lon=[float(lon1), float(lon2)],
        lat=[float(lat1), float(lat2)],
        marker={'size': 10},
        line=dict(width=2, color='blue')
    ))

map.update_layout(
    margin={'l': 50, 't': 50, 'b': 50, 'r': 50},
    mapbox={
        'center': {'lon': float(lon1), 'lat': float(lat1)},
        'style': "stamen-terrain",
        'zoom': 5
    }
)

map.show()
