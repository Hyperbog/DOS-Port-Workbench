image 0000:0000 0008 21CD30B4
stack_words 7
start 10F5:09DF first_opcode stack1=03B0
watch 10F5:0D89 fetch_after_short
watch 10F5:09F7 branch_taken
watch 10F5:09FB fetch_branch_target
watch 10F5:0DBF import_operand
watch 10F5:0DD0 resolve_import
watch 10F5:0DD7 import_stored
watch 10F5:0DE0 fetch_after_import
watch 10F5:0A87 fetch_after_push
watch 10F5:0DEA call_argc
watch 10F5:0E00 marshal_last
watch 10F5:0E0D marshal_first
watch 10F5:0E3F far_call
stop 0C7E:04F9 set_palette_entry
