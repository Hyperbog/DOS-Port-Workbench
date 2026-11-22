image 0000:0000 0008 21CD30B4
stack_words 7
start 0DDD:0642 interface_entry
watch 0DDD:07B5 interface_last_call
watch 0DDD:07BA interface_last_return
watch 0DDD:07BB interface_set_flag
watch 0DDD:07C4 interface_retf
watch 10F5:0E42 vm_resume
watch 10F5:0E4F store_low
watch 10F5:0E52 store_high
watch 10F5:0E56 result_stored
watch 10F5:0E66 fetch_import
watch 10F5:0DBF import_operand
watch 10F5:0DD0 replace_low
watch 10F5:0DD7 import_stored
watch 10F5:0DE0 fetch_after_import
watch 10F5:0A87 fetch_constant
watch 10F5:0D89 fetch_after_constant
watch 10F5:0DEA call_argc
watch 10F5:0E00 marshal_last
watch 10F5:0E0D marshal_first
watch 10F5:0E3F far_call
stop 0C7E:0B17 wipe_window_entry
