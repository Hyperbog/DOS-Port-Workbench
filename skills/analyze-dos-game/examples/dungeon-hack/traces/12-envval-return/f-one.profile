image 0000:0000 0008 21CD30B4
stack_words 5
start 0A4F:0DE1 envval_entry stack3=016C
watch 0000:3A56 match_name
watch 0000:3338 decimal_digit
watch 0A4F:0E16 envval_retf
watch 10F5:0E56 result_stored
watch 10F5:0CCE fetch_setb
watch 10F5:0AE8 fetch_brf
watch 10F5:0A14 test_condition
stop 10F5:0A21 branch_target
