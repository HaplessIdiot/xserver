amdgpu_srcs = [
  'amdgpu_driver.c',
  'amdgpu_accel.c',
  'amdgpu_crtc.c',
  'amdgpu_dri2.c',
  'amdgpu_dri3.c',
  'amdgpu_kms.c',
  'amdgpu_pageflip.c',
  'amdgpu_present.c',
  'amdgpu_vblank.c',
]
if build_modesetting
   subdir('modesetting')
endif

if get_option('xf86-video-amdgpu')
    subdir('amdgpu')
endif
