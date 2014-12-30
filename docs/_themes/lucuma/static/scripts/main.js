function setupDropdowns(e){
    $(document).on('click', '[data-toggle="dropdown"]', function(e){
        e.preventDefault();
        e.stopPropagation();
        setupDropdown(this);
    });
}
setupDropdowns();

function setupDropdown(dd){
    var $dd = $(dd);
    var targetSel = $dd.attr('href');
    var $target = $(targetSel);
    if ($target.is(':visible')){
        $target.slideUp();
    } else {
        $target.slideDown();
    }
}
