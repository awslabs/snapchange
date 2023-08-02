#/bin/bash
docker run --rm \
  -t \
  -v $PWD:/out \
  --entrypoint "/bin/sh" snapchange_example3:target -c "/opt/FFmpeg/ffmpeg -i /out/$1"