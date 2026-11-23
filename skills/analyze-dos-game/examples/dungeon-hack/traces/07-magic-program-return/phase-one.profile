image 0000:0000 0008 21CD30B4
stack_words 7
start 0B62:0124 create_program_retf
watch 10F5:0E42 vm_resume
watch 10F5:0E4F store_low
watch 10F5:0E52 store_high
watch 10F5:0E56 result_stored
watch 10F5:0E5B release_arguments
watch 10F5:0E66 fetch_import
watch 10F5:0DBF import_operand
watch 10F5:0DD0 replace_low
watch 10F5:0DD7 import_stored
watch 10F5:0DE0 fetch_after_import
watch 10F5:0A87 fetch_constant
watch 10F5:0DA0 fetch_after_constant
watch 10F5:0DEA call_argc
watch 10F5:0E00 marshal_last
watch 10F5:0E0D marshal_first
watch 10F5:0E3F far_call
stop 0B62:00A8 next_create_program_entry
