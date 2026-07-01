# WDTT Plus icon pack

Основная иконка — готовый PNG-арт, не VectorDrawable.

## Файлы

- `docs/icon-sources/wdtt_plus_icon.png` — исходник.
- `app/src/main/res/mipmap-*/ic_launcher.png` — legacy launcher.
- `app/src/main/res/mipmap-*/ic_launcher_round.png` — legacy round.
- `app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml` — adaptive icon.
- `app/src/main/res/drawable/ic_launcher_foreground.png` — PNG foreground.
- `app/src/main/res/drawable/ic_launcher_background.png` — dark background.
- `app/src/main/res/drawable/ic_launcher_monochrome.xml` — Android 13 themed icon.
- `app/src/main/res/drawable/ic_notification_icon.xml` — status bar notification icon.
- `app/src/main/res/drawable/ic_tile_logo.xml` — Quick Settings tile icon.

Полную 3D-иконку не перерисовывать через XML/SVG. VectorDrawable используется только для monochrome/notification/tile.
