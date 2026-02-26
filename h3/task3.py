import h3

lat, lng = 43.2077486, 76.6690457

h3_cell7 = h3.latlng_to_cell(lat, lng, 7)
h3_cell8 = h3.latlng_to_cell(lat, lng, 8)
h3_cell9 = h3.latlng_to_cell(lat, lng, 9)
h3_cell10 = h3.latlng_to_cell(lat, lng, 10)

print(f"h3 cell for SDU at resolution 7 is: {h3_cell7}")
print(f"h3 cell for SDU at resolution 8 is: {h3_cell8}")
print(f"h3 cell for SDU at resolution 9 is: {h3_cell9}")
print(f"h3 cell for SDU at resolution 10 is: {h3_cell10}")