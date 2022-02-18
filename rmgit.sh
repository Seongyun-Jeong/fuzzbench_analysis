for file in $(ls)
    do
        if [ -d $file ]; then
            echo $file
            cd $file
            rm -rf .git
            cd ..
        fi
    done