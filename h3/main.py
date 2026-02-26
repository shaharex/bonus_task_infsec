import h3

lat, lng = 43.2077486, 76.6690457

h3_cell = h3.latlng_to_cell(lat, lng, 9)

print(f"h3 cell for SDU at resolution 9 is: {h3_cell}")