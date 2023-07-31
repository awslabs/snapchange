#/bin/bash
# docker run --rm -it -v $PWD:/out --entrypoint "sh -c '/opt/tiff-4.0.4/build/bin/tiffinfo \"/out/$1\"'" snapchange_example2:target
docker run --rm -t -v $PWD:/out --entrypoint "/bin/sh" snapchange_example2:target -c "/opt/tiff-4.0.4/build/bin/tiffinfo /out/$1"
