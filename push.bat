@echo off
git stash
git pull --rebase
git stash pop
git add -A
git commit -m "Update 08.04"
git push
pause
