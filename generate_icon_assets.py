from PIL import Image, ImageDraw
from pathlib import Path

SRC = Path("docs/icon-sources/wdtt_plus_icon.png")
ROOT = Path("app/src/main/res")
src = Image.open(SRC).convert("RGBA")
side = min(src.size)
src = src.crop(((src.width-side)//2, (src.height-side)//2, (src.width+side)//2, (src.height+side)//2))

sizes = {"mipmap-mdpi":48, "mipmap-hdpi":72, "mipmap-xhdpi":96, "mipmap-xxhdpi":144, "mipmap-xxxhdpi":192}

def round_icon(img, size):
    im = img.resize((size,size), Image.Resampling.LANCZOS)
    mask = Image.new("L",(size,size),0)
    ImageDraw.Draw(mask).ellipse((0,0,size-1,size-1), fill=255)
    out = Image.new("RGBA",(size,size),(0,0,0,0))
    out.paste(im,(0,0),mask)
    return out

for folder, size in sizes.items():
    out_dir = ROOT / folder
    out_dir.mkdir(parents=True, exist_ok=True)
    src.resize((size,size), Image.Resampling.LANCZOS).save(out_dir/"ic_launcher.png")
    round_icon(src,size).save(out_dir/"ic_launcher_round.png")

fg = Image.new("RGBA",(432,432),(0,0,0,0))
icon = src.resize((397,397), Image.Resampling.LANCZOS)
fg.alpha_composite(icon,(17,17))
(ROOT/"drawable").mkdir(parents=True, exist_ok=True)
fg.save(ROOT/"drawable/ic_launcher_foreground.png")
