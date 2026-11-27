Songs for decode.rs's tests, made with ffmpeg (sine tones; silence for long.flac):

ffmpeg -f lavfi -i "sine=frequency=440:duration=1:sample_rate=48000" -ac 2 -c:a libopus -b:a 32k song.opus.ogg
ffmpeg -f lavfi -i "sine=frequency=440:duration=1:sample_rate=44100" -c:a libvorbis -q:a 0 song.vorbis.ogg
ffmpeg -f lavfi -i "sine=frequency=440:duration=1:sample_rate=44100" -c:a libmp3lame -b:a 64k song.mp3
ffmpeg -f lavfi -i "sine=frequency=440:duration=1:sample_rate=44100" -c:a flac song.flac
ffmpeg -f lavfi -i "anullsrc=r=8000:cl=mono" -t 370 -c:a flac -compression_level 12 long.flac
