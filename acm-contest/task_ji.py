n, m = map(int, input().split())

songs = []
total_a = 0
total_b = 0

for _ in range(n):
    a, b = map(int, input().split())
    songs.append((a, b))
    total_a += a
    total_b += b

if total_b > m:
    print(-1)
    exit()

if total_a <= m:
    print(0)
    exit()

need = total_a - m


savings = []
for a, b in songs:
    savings.append(a - b)

savings.sort(reverse=True)

freed = 0
count = 0

for s in savings:
    freed += s
    count += 1
    if freed >= need:
        print(count)
        break
