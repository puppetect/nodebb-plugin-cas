"use strict";

$(document).ready(function () {

    $(window).on('action:app.loggedOut', function(event, data) {
        var service = window.location.href.split('?')[0];
        var url = `${config.CASServerPrefix}/logout?service=${service}`;
        console.log(`[action:app.loggedOut] data.next=${url}`);
        data.next = url;
    });
}); 