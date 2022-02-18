recursive() {
    for file in $(ls)
    do
        if [ -d $file ]; then
            echo "going to " $(pwd) $file
            cd $file
            recursive
            cd ..
        else
            case $file in
                Dockerfile)
                    echo $file "found"
                    cat Dockerfile | grep "git clone">> /home/jsy01/fuzzbench_analysis/list/clonelist.txt
                    ;;
                *)
                    echo $file "pass"
                    ;;
            esac
        fi
    done
}

cd ../fuzzbench/benchmarks
# cd testdir
recursive

echo "hi"
#단점 : -로 시작하는 디렉토리에는 접근을 못하는 ㅈ버그가 있다. ex: cd -bug-syntax =>  
# bash: cd: -b: invalid option
# cd: usage: cd [-L|[-P [-e]] [-@]] [dir]
# 이따위로 나와서 실패! 그냥 가서 직접 지우는수밖에 없을듯하다.
# 이후에 빈 디렉토리 지우는 코드도 만들어야될듯?