"""Test-only range representation projection shared with the Rust oracle."""
import struct
def merge_points(points):
    rows=[]
    for point in sorted(set(points)):
        if rows and point==rows[-1][1]+1:rows[-1][1]=point
        else:rows.append([point,point])
    return struct.pack('<Q',len(rows))+b''.join(struct.pack('<QQ',*row)for row in rows)

