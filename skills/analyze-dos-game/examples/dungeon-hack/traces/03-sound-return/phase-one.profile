image 0000:0000 0008 21CD30B4
start 0BB9:07F3 sound_entry
watch 0BB9:0C58 sound_epilogue
watch 0BB9:0C5D sound_retf
watch 10F5:0E42 vm_resume
watch 10F5:0E4F store_low
watch 10F5:0E52 store_high
watch 10F5:0E56 result_stored
watch 10F5:0E66 fetch_import
watch 10F5:0DBF import_operand
watch 10F5:0DD0 replace_low
watch 10F5:0DD7 import_stored
watch 10F5:0DE0 fetch_call
watch 10F5:0DEA call_argc
watch 10F5:0E3F far_call
stop 0C7E:000E graphics_entry
