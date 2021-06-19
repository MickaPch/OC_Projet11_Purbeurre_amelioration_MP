var background_image = $("#store_image_url").val();

var masthead = document.getElementsByClassName('masthead')[0];

masthead.style.backgroundImage = "url('" + background_image + "')";

var ingredients = $("#ingredients").html();

var replace_ingredients = ingredients.replace(/_([^_]*)_/g, '<strong>&nbsp;$1&nbsp; </strong>');

$("#ingredients").html(replace_ingredients);

$('#show_product_infos').click(function() {
    if ($("#product_informations").hasClass('show')) {
        $("#product_informations").collapse('hide');
        $(this).html("Afficher les informations de ce produit");
    } else {
        $("#product_informations").collapse('show');
        $(this).html("Masquer les informations de ce produit");
    }
});

var selected_products = new Object();
var selected_type = new String();

$(document).on('click', ".select-product", function() {
    var product = $(this).parent();
    var product_checkbox = product.find('.select-checkbox');
    var code = product.find('.store-code').html();
    var name = product.find('.product-name').html();
    if ( product.find('.save-or-delete').find('a').hasClass('save-product') ) {
        selected_type = "save";
    } else if ( product.find('.save-or-delete').find('a').hasClass('delete-product') ) {
        selected_type = "delete";
    } else {
        alert('error in select type');
    }

    if ( selected_type == 'save' ){
        $(".registered-checkbox").attr('hidden', true);
        if ( product.hasClass("product-deselected") ) {
            product
            .removeClass("product-deselected")
            .addClass("product-selected");
            product_checkbox
            .removeClass("checkbox-deselected")
            .addClass("checkbox-selected");
            selected_products[code] = name;
        } else {
            product
            .removeClass("product-selected")
            .addClass("product-deselected");
            product_checkbox
            .removeClass("checkbox-selected")
            .addClass("checkbox-deselected");
            delete selected_products[code];
        }
    } else if ( selected_type == 'delete' ){
        $(".new-checkbox").attr('hidden', true);
        if ( product.hasClass("product-deselected") ) {
            product
            .removeClass("product-deselected")
            .addClass("product-selected");
            product_checkbox
            .removeClass("checkbox-registered")
            .addClass("checkbox-delete");
            selected_products[code] = name;
        } else {
            product
            .removeClass("product-selected")
            .addClass("product-deselected");
            product_checkbox
            .removeClass("checkbox-delete")
            .addClass("checkbox-registered");
            delete selected_products[code];
        }
    } else {
        alert('error in selected type');
    }
    
    
    if ( Object.keys(selected_products).length == 0 ) {
        $("#save_products").attr("hidden", true);
        $("#delete_products").attr("hidden", true);
        $(".inactive-product").removeClass('inactive-product').addClass('select-product').attr('disabled', false);
        $(".new-checkbox").attr('hidden', false);
        $(".registered-checkbox").attr('hidden', false);
        $(".product").addClass('select-product').removeClass('inactive-product');
        selected_type = new String();
    } else {
        if ( selected_type == 'save' ) {
            $(".registered-product").removeClass('select-product').addClass('inactive-product');
            $("#save_products").attr("hidden", false);
            $("#delete_products").attr("hidden", true);
            $(".delete-product").removeClass('select-product').addClass('inactive-product').attr('disabled', true);
            if ( Object.keys(selected_products).length == 1 ) {
                $("#btn_save").html('Sauvegarder le produit sélectionné');
                $("#btn_connect_product").html('Se connecter pour enregistrer le produit sélectionné');
            } else {
                $("#btn_save").html('Sauvegarder les ' + Object.keys(selected_products).length + ' produits sélectionnés')
                $("#btn_connect_product").html('Se connecter pour enregistrer les ' + Object.keys(selected_products).length + ' produits sélectionnés');
            }
        } else if ( selected_type == 'delete' ) {
            $(".product").removeClass('select-product').addClass('inactive-product');
            $(".registered-product").addClass('select-product').removeClass('inactive-product');
            $("#save_products").attr("hidden", true);
            $("#delete_products").attr("hidden", false);
            $(".save-product").removeClass('select-product').addClass('inactive-product').attr('disabled', true);
            if ( Object.keys(selected_products).length == 1 ) {
                $("#btn_delete").html('Supprimer le produit sélectionné');
                $("#btn_connect_product").html('Se connecter pour supprimer le produit sélectionné');
            } else {
                $("#btn_delete").html('Supprimer les ' + Object.keys(selected_products).length + ' produits sélectionnés')
                $("#btn_connect_product").html('Se connecter pour supprimer les ' + Object.keys(selected_products).length + ' produits sélectionnés');
            }
        } else {
            alert('error in selected type')
        }
    }
});

$("#btn_save").click(function(e) {
    e.preventDefault();
    $("#products_to_save").val(Object.keys(selected_products));
    $("#form_save").submit();
});

$("#btn_delete").click(function(e) {
    e.preventDefault();
    $("#products_to_delete").val(Object.keys(selected_products));
    $("#form_delete").submit();
});

$("#btn_connect_product").click(function(e) {
    e.preventDefault();
    $("#collapseLogin").collapse('show');
    $("#id_connect-user_login").focus();
});

$(".save-product").click(function(e) {
    e.preventDefault();
    if (!($(this).hasClass('inactive-product'))) {
        var product_code = $(this).parent().parent().find(".store-code").html();
        $("#products_to_save").val(product_code);
        $("#form_save").submit();
    }
});

$(".delete-product").click(function(e) {
    e.preventDefault();
    if (!($(this).hasClass('inactive-product'))) {
            var product_code = $(this).parent().parent().find(".store-code").html();
        $("#products_to_delete").val(product_code);
        $("#form_delete").submit();
    }
});