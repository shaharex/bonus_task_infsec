import pandas as pd
import h3

h3cel = h3.latlng_to_cell(49.1767, 74.1811, 9)
print(h3cel)


data = {
    'trip_id': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    'latitude': [49.1767, 49.1768, 49.1770, 49.1800, 49.1805, 49.1765, 49.1769, 49.1810, 49.1820, 49.1767],
    'longitude': [74.1811, 74.1812, 74.1813, 74.1850, 74.1855, 74.1810, 74.1814, 74.1860, 74.1870, 74.1811],
}

df = pd.DataFrame(data=data)

df['h3_cell'] = df.apply(lambda row: h3.latlng_to_cell(row['latitude'], row['longitude'], 9), axis=1)

print(df)





# Task 4: Measure Spatial Demand Inequality
# Group and compute percentages
counts = df.groupby('h3_cell').size().reset_index(name='trip_count') 
counts['percentage'] = (counts['trip_count'] / counts['trip_count'].sum()) * 100 
counts = counts.sort_values(by='percentage', ascending=False) 

# Calculate top 20% concentration
top_20_count = int(len(counts) * 0.2) or 1 # Ensure at least 1 cell
top_20_percentage = counts.iloc[:top_20_count]['percentage'].sum() 

print(counts)
print(f"Top 20% of cells generate {top_20_percentage:.2f}% of trips.")



# Task 5: Compare Demand Stability
df['h3_res8'] = df.apply(lambda row: h3.latlng_to_cell(row['Latitude'], row['longitude'], 8), axis=1) 
df['h3_res9'] = df.apply(lambda row: h3.latlng_to_cell(row['Latitude'], row['longitude'], 9), axis=1) 

res8_agg = df.groupby('h3_res8').size().sort_values(ascending=False).head(3) 
res9_agg = df.groupby('h3_res9').size().sort_values(ascending=False).head(3) 

print("Top Cells Res 8:\n", res8_agg)
print("\nTop Cells Res 9:\n", res9_agg)


# Task 6: Compare Different Resolutions
lat, lon = 49.176732, 74.181127 
resolutions = [7, 8, 9, 10] 

for res in resolutions:
    idx = h3.latlng_to_cell(lat, lon, res)
    print(f"Res {res}: {idx}")


"""
Architecture Thinking

Placement: H3 conversion should primarily happen in the Data Processing Layer. This allows the raw coordinates to be indexed once before being passed to both the Analytics service for historical reporting and the API layer for real-time querying.
+1


Timing: For dispatching and real-time surges, H3 indexing should be real-time. For long-term profitability analysis or city planning, batch processing is more efficient to handle large volumes of historical data.


High Resolution Risks: If resolution is too high in a large-scale system, you face "index explosion," where the volume of unique IDs exceeds memory limits. Furthermore, it creates a "sparse data" problem where almost every cell contains only one or zero trips, making statistical analysis impossible
"""




