
$('[data-toggle="dropdown"]').each(function(e){
    var ANIM_DURATION = 50;
    var $this = $(this);
    var targetSel = $(this).attr('href');
    var $target = $(targetSel);


    function hideOnClickOutside(e){
        if ($(e.target).closest($target).length === 0){
            hideTarget();
        }
    }

    function hideTarget(){
        $this.removeClass('active');
        $target.fadeOut(ANIM_DURATION);
        $(document).off('click', hideOnClickOutside);
    }

    function showTarget(){
        $this.addClass('active');
        $target.fadeIn(ANIM_DURATION);
        $(document).on('click', hideOnClickOutside);
    }

    $this.on('click', function(e){
        e.preventDefault();
        e.stopPropagation();
        if ($target.is(':visible')){
            hideTarget();
        } else {
            showTarget();
        }
        return false;
    });
});
