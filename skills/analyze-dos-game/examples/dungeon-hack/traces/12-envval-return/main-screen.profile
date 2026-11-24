image 0000:0000 0008 21CD30B4
stack_words 21
start 0A4F:0DE1 envval_entry stack3=016C
watch 0000:3A56 match_name
watch 0000:3A5E value_address
watch 0A4F:0DF2 lookup_return
watch 0A4F:0E0C convert_call
watch 0000:3338 decimal_digit
watch 0A4F:0E11 converted
watch 0A4F:0E16 envval_retf
watch 10F5:0E42 vm_resume
watch 10F5:0E4F store_low
watch 10F5:0E52 store_high
watch 10F5:0E56 result_stored
watch 10F5:0E66 fetch_resume
watch 10F5:0A87 fetch_short
watch 10F5:0D89 fetch_after_short
watch 10F5:0CCE fetch_setb
watch 10F5:0AE8 fetch_brf
watch 10F5:0A14 test_condition
watch 10F5:0A30 fetch_import
watch 10F5:0DD0 resolve_import
watch 10F5:0DE0 fetch_first_push
watch 10F5:0DEA call_argc
watch 10F5:0E00 marshal_a
watch 10F5:0E0D marshal_b
watch 10F5:0E1A marshal_c
watch 10F5:0E27 marshal_d
watch 10F5:0E3F far_call
stop 0C7E:0349 draw_bitmap_entry
