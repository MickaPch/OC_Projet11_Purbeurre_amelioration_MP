$("#id_email").change(function() {
    var email = $(this).val();
    var new_content = new String;

    if (email != "") {
        $.ajax({
            url: "/user/email_verification/",
            type: "POST",
            data: {email: email}
        }).done(function(response) {
            if (response == "email nok") {
                new_content += "<div class='invalid-input'>Veuillez entrer une adresse mail conforme.</div>";
                $("#id_email").addClass('is-invalid').removeClass('is-valid');
            } else {
                new_content += "<div class='valid-input'>Le format de cet email est conforme.</div>";
                $("#id_email").addClass('is-valid').removeClass('is-invalid');
            }
            $("#id_email").attr("data-content", new_content);
            var popover = $("#id_email").data('bs.popover');
            popover.setContent();
        }).fail(function() {
            console.log('failed');
        });
    } else {
        new_content += "<div class='invalid-input'>Veuillez entrer votre adresse mail.</div>"
        $("#id_email").attr("data-content", new_content);
        var popover = $("#id_email").data('bs.popover');
        popover.setContent();
        $("#id_email").addClass('is-invalid').removeClass('is-valid');
    }
}).focus(function() {
    $("#id_email").popover('show');
}).blur(function() {
    $("#id_email").popover('hide');
    var email = $("#id_email").val();
    var new_content = new String;
    $.ajax({
        url: "/user/email_verification/",
        type: "POST",
        data: {email: email}
    }).done(function(response) {
        console.log(response)
        if (response == "email nok") {
            new_content += "<div class='invalid-input'>Veuillez entrer une adresse mail conforme.</div>";
            $("#id_email").addClass('is-invalid').removeClass('is-valid');
        } else {
            new_content += "<div class='valid-input'>Le format de cet email est conforme.</div>";
            $("#id_email").addClass('is-valid').removeClass('is-invalid');
        }
        $("#id_email").attr("data-content", new_content);
    }).fail(function() {
        console.log('failed');
    });
});

$("#id_user_login").change(function() {
    var user_login = $(this).val();
    var new_content = new String;

    if (user_login != "") {
        $.ajax({
            url: "/user/check_user_login/",
            type: "POST",
            data: {user_login: user_login}
        }).done(function(response) {
            if (response == "login not available") {
                new_content += "<div class='invalid-input'>Ce login est déjà utilisé par un autre utilisateur.</div>"
                $("#id_user_login").addClass('is-invalid').removeClass('is-valid');
            } else if (response == "Incorrect login format") {
                new_content += "<div class='invalid-input'>Format incorrect (Lettres et chiffres acceptées seulement).</div>"
                $("#id_user_login").addClass('is-invalid').removeClass('is-valid');
            } else if (response == "login ok") {
                new_content += "<div class='valid-input'>Ce login est disponible.</div>"
                $("#id_user_login").addClass('is-valid').removeClass('is-invalid');
            }
            $("#id_user_login").attr("data-content", new_content);
            var popover = $("#id_user_login").data('bs.popover');
            popover.setContent();
        }).fail(function() {
            console.log('failed');
        });
    } else {
        $(this).removeClass('is-valid is-invalid');
        new_content += "<div>Facultatif. Peut être utilisé comme identifiant de connexion.</div>"
        $("#id_user_login").attr("data-content", new_content);
        var popover = $("#id_user_login").data('bs.popover');
        popover.setContent();

    }
}).focus(function() {
    $("#id_user_login").popover('show');
}).blur(function() {
    $("#id_user_login").popover('hide');
});

$("#id_pwd").keyup(function() {
    var pwd = $(this).val();
    var new_content = new String;

    if (pwd != "") {
        $.ajax({
            url: "/user/check_pwd/",
            type: "POST",
            data: {pwd: pwd}
        }).done(function(response) {
            if (response == "Mot de passe OK") {
                $("#id_pwd").addClass('is-valid').removeClass('is-invalid');
                new_content += "<div class='valid-input'>Au moins 8 caractères.</div>"
                new_content += "<div class='valid-input'>Au moins 1 lettre majuscule.</div>"
                new_content += "<div class='valid-input'>Au moins 1 chiffre.</div>"
                new_content += "<div class='valid-input'>Au moins 1 caractère spécial.</div>"
            } else {
                $("#id_pwd").addClass('is-invalid').removeClass('is-valid');
                var response_array = response;
                if (response_array.includes('This password is too common.')) {
                    new_content += "<div class='invalid-input'>Mot de passe trop commun.</div>"
                }
                if (response_array.includes('This password is too short. It must contain at least 8 characters.')) {
                    new_content += "<div class='invalid-input'>Au moins 8 caractères.</div>"
                } else {
                    new_content += "<div class='valid-input'>Au moins 8 caractères.</div>"
                }
                if (response_array.includes('This password must contain at least one capital.')) {
                    new_content += "<div class='invalid-input'>Au moins 1 lettre majuscule.</div>"
                } else {
                    new_content += "<div class='valid-input'>Au moins 1 lettre majuscule.</div>"
                }
                if (response_array.includes('This password must contain at least one digit.')) {
                    new_content += "<div class='invalid-input'>Au moins 1 chiffre.</div>"
                } else {
                    new_content += "<div class='valid-input'>Au moins 1 chiffre.</div>"
                }
                if (response_array.includes('This password must contain at least one special character.')) {
                    new_content += "<div class='invalid-input'>Au moins 1 caractère spécial.</div>"
                } else {
                    new_content += "<div class='valid-input'>Au moins 1 caractère spécial.</div>"
                }
            }
            $("#id_pwd").attr("data-content", new_content);
            var popover = $("#id_pwd").data('bs.popover');
            popover.setContent();
        }).fail(function() {
            console.log('failed');
        });
    } else {
        $(this).addClass('is-invalid').removeClass('is-valid');
        new_content += "<div class='invalid-input'>Au moins 8 caractères.</div>"
        new_content += "<div class='invalid-input'>Au moins 1 lettre majuscule.</div>"
        new_content += "<div class='invalid-input'>Au moins 1 chiffre.</div>"
        new_content += "<div class='invalid-input'>Au moins 1 caractère spécial.</div>"
        $("#id_pwd").attr("data-content", new_content);
        var popover = $("#id_pwd").data('bs.popover');
        popover.setContent();
    }
    popover_pwd_confirm()
}).focus(function() {
    $("#id_pwd").popover('show');
}).blur(function() {
    $("#id_pwd").popover('hide');
});

$("#show_pwd").on('click', function() {
    if ( $("#id_pwd").attr('type') == 'password' ) {
        $("#id_pwd").attr('type', 'text');
        $(this).html('<i class="fas fa-eye-slash fa-lg"></i>').attr('title', 'Masquer le mot de passe');
    } else {
        $("#id_pwd").attr('type', 'password');
        $(this).html('<i class="fas fa-eye fa-lg"></i>').attr('title', 'Voir le mot de passe');
    }
});

$("#id_pwd_confirm").keyup(function() {
    popover_pwd_confirm()
    var popover = $("#id_pwd_confirm").data('bs.popover');
    popover.setContent();
}).focus(function() {
    $("#id_pwd_confirm").popover('show');
}).blur(function() {
    $("#id_pwd_confirm").popover('hide');
});

$("#show_pwd_confirm").on('click', function() {
    if ( $("#id_pwd_confirm").attr('type') == 'password' ) {
        $("#id_pwd_confirm").attr('type', 'text');
        $(this).html('<i class="fas fa-eye-slash fa-lg"></i>').attr('title', 'Masquer le mot de passe');
    } else {
        $("#id_pwd_confirm").attr('type', 'password');
        $(this).html('<i class="fas fa-eye fa-lg"></i>').attr('title', 'Voir le mot de passe');
    }
});

$("#id_cgu").change(function() {
    if ($(this).is(':checked')) {
        $(this).addClass('is-valid').removeClass('is-invalid');
    } else {
        $(this).addClass('is-invalid').removeClass('is-valid');
    }
});

$("#form_new").on('submit', function(event) {
    event.preventDefault();
    var form = $(this);

    send_post(form);

});

function send_post(form) {
    var new_content = new String;
    if (
        $("#id_email").hasClass('is-valid')
        && !($("#id_user_login").hasClass('is-invalid'))
        && $("#id_pwd").hasClass('is-valid')
        && $("#id_pwd_confirm").hasClass('is-valid')
        && $("#id_cgu").hasClass('is-valid')
    ) {
        $.ajax({
            url: form.attr("data-new-account"),
            data: form.serialize(),
            dataType: 'json',
            method: "POST",
            success: function (data) {
                if (data.ok) {
                    alert('Le compte a bien été créé')
                    window.location.replace(data.url);
                } else {
                    alert('Erreur')
                }
            },
            error: function(xhr, errmsg, err) {
                console.log(errmsg);
            }
        }).done(function(response) {
            if (response == "email disponible") {
                new_content += "<div class='valid-input'>Cet email est valable et disponible.</div>"
                $("#id_email").addClass('is-valid').removeClass('is-invalid');
            } else if (response == "email pris") {
                new_content += "<div class='invalid-input'>Cet email est déjà utilisé par un autre utilisateur.</div>"
                $("#id_email").addClass('is-invalid').removeClass('is-valid');
            } else {
                new_content += "<div class='invalid-input'>Le format de l'email n'est pas valide.</div>"
                $("#id_email").addClass('is-invalid').removeClass('is-valid');
            }
            $("#id_email").attr("data-content", new_content);
            var popover = $("#id_email").data('bs.popover');
            popover.setContent();
        }).fail(function() {
            console.log('failed');
        });
    } else if ( $("#id_email").hasClass('is-invalid') ) {
        $("#id_email").focus().popover('show');
    } else if ( $("#id_user_login").hasClass('is-invalid') ) {
        $("#id_user_login").focus().popover('show');
    } else if ( $("#id_pwd").hasClass('is-invalid') ) {
        $("#id_pwd").focus().popover('show');
    } else if ( $("#id_pwd_confirm").hasClass('is-invalid') ) {
        $("#id_pwd_confirm").focus().popover('show');
    } else if ( $("#id_cgu").hasClass('is-invalid') ) {
        $("#id_cgu").focus();
    }
}

function popover_pwd_confirm() {
    var pwd_confirm = $("#id_pwd_confirm").val();
    var pwd = $("#id_pwd").val();
    var new_content = new String;

    if (
        pwd == ""
        || pwd_confirm == ""
        || pwd_confirm != pwd
    ) {
        new_content += "<div class='invalid-input'>Les mots de passe ne correspondent pas.</div>"
        $("#id_pwd_confirm").addClass('is-invalid').removeClass('is-valid');
    } else {
        new_content += "<div class='valid-input'>Les mots de passe correspondent.</div>"
        $("#id_pwd_confirm").addClass('is-valid').removeClass('is-invalid');
    }
    $("#id_pwd_confirm").attr("data-content", new_content);
}
