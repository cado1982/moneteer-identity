/// <binding AfterBuild='scripts' />
var gulp = require("gulp");
var merge = require("gulp-sequence");

var deps = {
    "jquery": {
        "dist/*": ""
    },
    "@clr/ui": {
        "*": ""
    },
    "@clr/icons": {
        "*": ""
    }
}

gulp.task("scripts", function () {
    var streams = [];

    for (var prop in deps) {
        console.log("Prepping Scripts for: " + prop);
        for (var itemProp in deps[prop]) {
            streams.push(gulp.src("node_modules/" + prop + "/" + itemProp)
                .pipe(gulp.dest("wwwroot/lib/" + prop + "/" + deps[prop][itemProp])));
        }
    }

    return merge(streams);
});