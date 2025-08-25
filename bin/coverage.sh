forge coverage --report lcov

genhtml lcov.info --branch-coverage --function-coverage --output-directory coverage-html
open coverage-html/index.html