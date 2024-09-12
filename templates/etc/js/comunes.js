
$(document).ready(function() {
    $.get("/obtener_comentarios", function(data) {

        const comentariosContainer = $('<div></div>');
        for (let i = 0; i < data.length; i++) {
            const comentario = data[i];
            const comentarioElement = $('<p></p>').text(JSON.stringify(comentario));
            comentariosContainer.append(comentarioElement);
        }
        $('body').append(comentariosContainer);
    });
});