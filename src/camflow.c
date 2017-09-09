/*
* CamFlow userspace provenance tool
*
* Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
*
* Copyright (C) 2016 Harvard University
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#define _XOPEN_SOURCE 500
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/camflow.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "provenance.h"
#include "provenancefilter.h"
#include "provenanceutils.h"

#define ARG_HELP                        "-h"
#define ARG_VERSION                     "-v"
#define ARG_STATE                       "-s"
#define ARG_ENABLE                      "-e"
#define ARG_ALL                         "-a"
#define ARG_COMPRESS                    "--compress"
#define ARG_FILE                        "--file"
#define ARG_TRACK_FILE                  "--track-file"
#define ARG_LABEL_FILE                  "--label-file"
#define ARG_OPAQUE_FILE                 "--opaque-file"
#define ARG_PROCESS                     "--process"
#define ARG_TRACK_PROCESS               "--track-process"
#define ARG_LABEL_PROCESS               "--label-process"
#define ARG_OPAQUE_PROCESS              "--opaque-process"
#define ARG_TRACK_IPV4_INGRESS          "--track-ipv4-ingress"
#define ARG_TRACK_IPV4_EGRESS           "--track-ipv4-egress"
#define ARG_FILTER_NODE                 "--node-filter"
#define ARG_FILTER_EDGE                 "--edge-filter"
#define ARG_PROPAGATE_FILTER_NODE       "--node-propagate-filter"
#define ARG_PROPAGATE_FILTER_EDGE       "--edge-propagate-filter"
#define ARG_FILTER_RESET                "--reset-filter"
#define ARG_SECCTX_FILTER               "--track-secctx"
#define ARG_CGROUP_FILTER               "--track-cgroup"
#define ARG_USER_FILTER                 "--track-user"
#define ARG_GROUP_FILTER                "--track-group"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define CMD_COLORED ANSI_COLOR_GREEN "%s" ANSI_COLOR_RESET
#define CMD_PARAMETER(str) " " ANSI_COLOR_YELLOW "<" str ">" ANSI_COLOR_RESET
#define CMD_WARNING(str) ANSI_COLOR_RED str ANSI_COLOR_RESET

void usage( void ){
  printf(CMD_COLORED " usage.\n", ARG_HELP);
  printf(CMD_COLORED " version.\n", ARG_VERSION);
  printf(CMD_COLORED " print provenance capture state.\n", ARG_STATE);
  printf(CMD_COLORED CMD_PARAMETER("bool") " enable/disable provenance capture.\n", ARG_ENABLE);
  printf(CMD_COLORED CMD_PARAMETER("bool") " activate/deactivate whole-system provenance capture.\n", ARG_ALL);
  printf(CMD_COLORED CMD_PARAMETER("bool") " activate/deactivate node compression.\n", ARG_COMPRESS);
  printf(CMD_COLORED CMD_PARAMETER("filename") " display provenance info of a file.\n", ARG_FILE);
  printf(CMD_COLORED CMD_PARAMETER("filename") CMD_PARAMETER("false/true/propagate") " set tracking.\n", ARG_TRACK_FILE);
  printf(CMD_COLORED CMD_PARAMETER("filename") CMD_PARAMETER("string") " applies label to the file.\n", ARG_LABEL_FILE);
  printf(CMD_COLORED CMD_PARAMETER("filename") CMD_PARAMETER("bool") " mark/unmark the file as opaque.\n", ARG_OPAQUE_FILE);
  printf(CMD_COLORED CMD_PARAMETER("pid") " display provenance info of a process.\n", ARG_PROCESS);
  printf(CMD_COLORED CMD_PARAMETER("pid") CMD_PARAMETER("false/true/propagate") " set tracking.\n", ARG_TRACK_PROCESS);
  printf(CMD_COLORED CMD_PARAMETER("pid") CMD_PARAMETER("string") " applies label to the process.\n", ARG_LABEL_PROCESS);
  printf(CMD_COLORED CMD_PARAMETER("pid") CMD_PARAMETER("bool") " mark/unmark the process as opaque.\n", ARG_OPAQUE_PROCESS);
  printf(CMD_COLORED CMD_PARAMETER("ip/mask:port") CMD_PARAMETER("track/propagate/record/delete") " track/propagate on bind.\n", ARG_TRACK_IPV4_INGRESS);
  printf(CMD_COLORED CMD_PARAMETER("ip/mask:port") CMD_PARAMETER("track/propagate/record/delete") " track/propagate on connect.\n", ARG_TRACK_IPV4_EGRESS);
  printf(CMD_COLORED CMD_PARAMETER("security context") CMD_PARAMETER("track/propagate/delete") " track/propagate based on security context.\n", ARG_SECCTX_FILTER);
  printf(CMD_COLORED CMD_PARAMETER("cgroup ino") CMD_PARAMETER("track/propagate/delete") " track/propagate based on cgroup.\n", ARG_CGROUP_FILTER);
  printf(CMD_COLORED CMD_PARAMETER("user name") CMD_PARAMETER("track/propagate/delete") " track/propagate based on user.\n", ARG_USER_FILTER);
  printf(CMD_COLORED CMD_PARAMETER("group name") CMD_PARAMETER("track/propagate/delete") " track/propagate based on group.\n", ARG_CGROUP_FILTER);
  printf(CMD_COLORED CMD_PARAMETER("type") CMD_PARAMETER("bool") " set node filter.\n", ARG_FILTER_NODE);
  printf(CMD_COLORED CMD_PARAMETER("type") CMD_PARAMETER("bool") " set edge filter.\n", ARG_FILTER_EDGE);
  printf(CMD_COLORED CMD_PARAMETER("type") CMD_PARAMETER("bool") " set propagate node filter.\n", ARG_PROPAGATE_FILTER_NODE);
  printf(CMD_COLORED CMD_PARAMETER("type") CMD_PARAMETER("bool") " set propagate edge filter.\n", ARG_PROPAGATE_FILTER_EDGE);
  printf(CMD_COLORED " reset filters.\n", ARG_FILTER_RESET);
}

#define is_str_track(str) ( strcmp (str, "track") == 0)
#define is_str_delete(str) ( strcmp (str, "delete") == 0)
#define is_str_propagate(str) ( strcmp (str, "propagate") == 0)
#define is_str_record(str) ( strcmp (str, "record") == 0)
#define is_str_true(str) ( strcmp (str, "true") == 0)
#define is_str_false(str) ( strcmp (str, "false") == 0)

void enable( const char* str ){
  if(!is_str_true(str) && !is_str_false(str)){
    printf("Excepted a boolean, got %s.\n", str);
    return;
  }

  if(provenance_set_enable(is_str_true(str))<0)
    perror("Could not enable/disable provenance capture");
}

void all( const char* str ){
  if(!is_str_true(str) && !is_str_false(str)){
    printf("Excepted a boolean, got %s.\n", str);
    return;
  }

  if(provenance_set_all(is_str_true(str))<0)
    perror("Could not activate/deactivate whole-system provenance capture");
}

void should_compress( const char* str ){
  if(!is_str_true(str) && !is_str_false(str)){
    printf("Excepted a boolean, got %s.\n", str);
    return;
  }

  if(provenance_should_compress(is_str_true(str))<0)
    perror("Could not activate/deactivate node compression.");
}

void state( void ){
  uint64_t filter=0;
  struct prov_ipv4_filter filters[100];
  struct secinfo sec_filters[100];
  struct nsinfo ns_filters[100];
  struct userinfo user_filters[100];
  struct passwd* pwd;
  struct groupinfo group_filters[100];
  struct group* grp;
  uint8_t buffer[256];
  int size;
  uint32_t machine_id;
  int i;

  provenance_get_machine_id(&machine_id);
  printf("Machine id: %u\n", machine_id);

  printf("Policy hash: ");
  size = provenance_policy_hash(buffer, 256);
  for(i=0; i<size; i++)
    printf("%0X", buffer[i]);
  printf("\n");

  printf("Provenance capture:\n");
  if(provenance_get_enable())
    printf("- capture enabled;\n");
  else
    printf("- capture disabled;\n");

  if( provenance_get_all() )
    printf("- all enabled;\n");
  else
    printf("- all disabled;\n");

  if( provenance_does_compress() )
    printf("- compress enabled;\n");
  else
    printf("- compress disabled;\n");

  provenance_get_node_filter(&filter);
  printf("\nNode filter (%0lx):\n", filter);

  provenance_get_relation_filter(&filter);
  printf("Relation filter (%0lx):\n", filter);

  provenance_get_propagate_node_filter(&filter);
  printf("\nPropagate node filter (%0lx):\n", filter);

  provenance_get_propagate_relation_filter(&filter);
  printf("Propagate relation filter (%0lx):\n", filter);

  size = provenance_ingress_ipv4(filters, 100*sizeof(struct prov_ipv4_filter));
  printf("IPv4 ingress filter (%ld).\n", size/sizeof(struct prov_ipv4_filter));
  for(i = 0; i < size/sizeof(struct prov_ipv4_filter); i++){
    printf("%s", uint32_to_ipv4str(filters[i].ip));
    printf("/%d", count_set_bits(filters[i].mask));
    printf(":%d ", ntohs(filters[i].port));

    if((filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
      printf("propagate");
    else if((filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
      printf("track");

    if((filters[i].op&PROV_SET_RECORD) == PROV_SET_RECORD)
      printf(" record");
    printf("\n");
  }

  size = provenance_egress_ipv4(filters, 100*sizeof(struct prov_ipv4_filter));
  printf("IPv4 egress filter (%ld).\n", size/sizeof(struct prov_ipv4_filter));
  for(i = 0; i < size/sizeof(struct prov_ipv4_filter); i++){
    printf("%s", uint32_to_ipv4str(filters[i].ip));
    printf("/%d", count_set_bits(filters[i].mask));
    printf(":%d ", ntohs(filters[i].port));

    if((filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
      printf("propagate");
    else if((filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
      printf("track");

    if((filters[i].op&PROV_SET_RECORD) == PROV_SET_RECORD)
      printf(" record");
    printf("\n");
  }

  size = provenance_secctx(sec_filters, 100*sizeof(struct secinfo));
  printf("Security context filter (%ld).\n", size/sizeof(struct secinfo));
  for(i = 0; i < size/sizeof(struct secinfo); i++){
    printf("%s ", sec_filters[i].secctx);
    if((sec_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
      printf("propagate");
    else if((sec_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
      printf("track");
    printf("\n");
  }

  size = provenance_ns(ns_filters, 100*sizeof(struct nsinfo));
  printf("Namespace filter (%ld).\n", size/sizeof(struct nsinfo));
  for(i = 0; i < size/sizeof(struct nsinfo); i++){
    printf("%u ", ns_filters[i].cgroupns);
    if((ns_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
      printf("propagate");
    else if((ns_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
      printf("track");
    printf("\n");
  }

  size = provenance_user(user_filters, 100*sizeof(struct userinfo));
  printf("User filter (%ld).\n", size/sizeof(struct userinfo));
  for(i = 0; i < size/sizeof(struct userinfo); i++){
    pwd = getpwuid(user_filters[i].uid);
    printf("%s ", pwd->pw_name);
    if((user_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
      printf("propagate");
    else if((user_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
      printf("track");
    printf("\n");
  }

  size = provenance_group(group_filters, 100*sizeof(struct groupinfo));
  printf("Group filter (%ld).\n", size/sizeof(struct groupinfo));
  for(i = 0; i < size/sizeof(struct groupinfo); i++){
    grp = getgrgid(group_filters[i].gid);
    printf("%s ", grp->gr_name);
    if((group_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
      printf("propagate");
    else if((group_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
      printf("track");
    printf("\n");
  }
}

void print_version(){
  printf("CamFlow %s\n", CAMFLOW_VERSION_STR);
}

void file( const char* path){
  union prov_elt inode_info;
  char id[PROV_ID_STR_LEN];
  char taint[TAINT_STR_LEN];
  int err;

  err = provenance_read_file(path, &inode_info);
  if(err < 0){
    perror("Could not read file provenance information.\n");
    exit(-1);
  }

  ID_ENCODE(prov_id_buffer(&inode_info), PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);
  printf("Identifier: %s\n", id);
  printf("Type: %lu\n", node_identifier(&inode_info).type);
  printf("ID: %lu\n", node_identifier(&inode_info).id);
  printf("Boot ID: %u\n", node_identifier(&inode_info).boot_id);
  printf("Machine ID: %u\n", node_identifier(&inode_info).machine_id);
  printf("Version: %u\n", node_identifier(&inode_info).version);
  TAINT_ENCODE(prov_taint(&(inode_info)), PROV_N_BYTES, taint, TAINT_STR_LEN);
  printf("Taint: %s\n", taint);
  printf("\n");
  if( provenance_is_tracked(&inode_info) )
    printf("File is tracked.\n");
  else
    printf("File is not tracked.\n");

  if( provenance_is_opaque(&inode_info) )
    printf("File is opaque.\n");
  else
    printf("File is not opaque.\n");

  if( provenance_does_propagate(&inode_info) )
    printf("File propagates tracking.\n");
  else
    printf("File is not propagating tracking.\n");
}

void process(uint32_t pid){
  union prov_elt process_info;
  char id[PROV_ID_STR_LEN];
  char taint[TAINT_STR_LEN];
  int err;

  err = provenance_read_process(pid, &process_info);
  if(err < 0){
    perror("Could not read process provenance information.\n");
    exit(-1);
  }

  ID_ENCODE(prov_id_buffer(&process_info), PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);
  printf("Identifier: %s\n", id);
  printf("Type: %lu\n", node_identifier(&process_info).type);
  printf("ID: %lu\n", node_identifier(&process_info).id);
  printf("Boot ID: %u\n", node_identifier(&process_info).boot_id);
  printf("Machine ID: %u\n", node_identifier(&process_info).machine_id);
  TAINT_ENCODE(prov_taint(&(process_info)), PROV_N_BYTES, taint, TAINT_STR_LEN);
  printf("Taint: %s\n", taint);
  printf("\n");
  if( provenance_is_tracked(&process_info) )
    printf("Process is tracked.\n");
  else
    printf("Process is not tracked.\n");

  if( provenance_is_opaque(&process_info) )
    printf("Process is opaque.\n");
  else
    printf("Process is not opaque.\n");

  if( provenance_does_propagate(&process_info) )
    printf("Process propagates tracking.\n");
  else
    printf("Process is not propagating tracking.\n");
}

#define CHECK_ATTR_NB(argc, min) if(argc < min){ usage();exit(-1);}
#define MATCH_ARGS(str1, str2) if(strcmp(str1, str2 )==0)

int main(int argc, char *argv[]){
  int err=0;
  uint64_t id;

  if(!provenance_is_present()){
    printf(ANSI_COLOR_RED"It appears CamFlow has not been installed on your machine.\n");
    printf("Please verify you are booted under the correct kernel version\n"ANSI_COLOR_RESET);
    exit(-1);
  }

  CHECK_ATTR_NB(argc, 2);
  // do it properly, but that will do for now

  MATCH_ARGS(argv[1], ARG_HELP){
    usage();
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_VERSION){
    print_version();
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_STATE){
    state();
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_ENABLE){
    CHECK_ATTR_NB(argc, 3);
    enable(argv[2]);
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_ALL){
    CHECK_ATTR_NB(argc, 3);
    all(argv[2]);
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_COMPRESS){
    CHECK_ATTR_NB(argc, 3);
    should_compress(argv[2]);
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_FILE){
    CHECK_ATTR_NB(argc, 3);
    file(argv[2]);
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_TRACK_FILE){
    CHECK_ATTR_NB(argc, 4);
    if( is_str_propagate(argv[3]) ){
      err = provenance_propagate_file(argv[2], true);
    }else {
      err = provenance_track_file(argv[2], is_str_true(argv[3]));
      if(err < 0)
        perror("Could not change tracking settings for this file.\n");
      if(!is_str_true(argv[3]))
        err = provenance_propagate_file(argv[2], false);
    }
    if(err < 0)
      perror("Could not change tracking settings for this file.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_LABEL_FILE){
    CHECK_ATTR_NB(argc, 4);
    err = provenance_label_file(argv[2], argv[3]);
    if(err < 0)
      perror("Could not change taint settings for this file.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_OPAQUE_FILE){
    CHECK_ATTR_NB(argc, 4);
    err = provenance_opaque_file(argv[2], is_str_true(argv[3]));
    if(err < 0)
      perror("Could not change opacity settings for this file.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_PROCESS){
    CHECK_ATTR_NB(argc, 3);
    process(atoi(argv[2]));
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_TRACK_PROCESS){
    CHECK_ATTR_NB(argc, 4);
    if( is_str_propagate(argv[3]) ){
      err = provenance_propagate_process(atoi(argv[2]), true);
    }else {
      err = provenance_track_process(atoi(argv[2]), is_str_true(argv[3]));
      if(err < 0)
        perror("Could not change tracking settings for this process.\n");
      if(!is_str_true(argv[3]))
        err = provenance_propagate_process(atoi(argv[2]), false);
    }
    if(err < 0)
      perror("Could not change tracking settings for this process.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_LABEL_PROCESS){
    CHECK_ATTR_NB(argc, 4);
    err = provenance_label_process(atoi(argv[2]), argv[3]);
    if(err < 0)
      perror("Could not change taint settings for this process.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_OPAQUE_PROCESS){
    CHECK_ATTR_NB(argc, 4);
    err = provenance_opaque_process(atoi(argv[2]), is_str_true(argv[3]));
    if(err < 0)
      perror("Could not change opacity settings for this process.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_TRACK_IPV4_INGRESS){
    CHECK_ATTR_NB(argc, 4);
    if( is_str_propagate( argv[3]) )
      err = provenance_ingress_ipv4_propagate(argv[2]);
    else if( is_str_record( argv[3]) )
      err = provenance_ingress_ipv4_record(argv[2]);
    else if( is_str_track(argv[3]))
      err = provenance_ingress_ipv4_track(argv[2]);
    else if( is_str_delete(argv[3]))
      err = provenance_ingress_ipv4_delete(argv[2]);

    if(err < 0)
      perror("Could not change ipv4 ingress.\n");
    else
      printf(CMD_WARNING("Only apply to newly created connection.\n"));
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_TRACK_IPV4_EGRESS){
    CHECK_ATTR_NB(argc, 4);
    if( is_str_propagate( argv[3]) )
      err = provenance_egress_ipv4_propagate(argv[2]);
    else if( is_str_record(argv[3]) )
      err = provenance_egress_ipv4_record(argv[2]);
    else if( is_str_track(argv[3]))
      err = provenance_egress_ipv4_track(argv[2]);
    else if( is_str_delete(argv[3]))
      err = provenance_egress_ipv4_delete(argv[2]);

    if(err < 0)
      perror("Could not change ipv4 egress.\n");
    else
      printf(CMD_WARNING("Only apply to newly created connection.\n"));

    return 0;
  }
  MATCH_ARGS(argv[1], ARG_SECCTX_FILTER){
    CHECK_ATTR_NB(argc, 4);
    if( is_str_propagate( argv[3]) )
      err = provenance_secctx_propagate(argv[2]);
    else if( is_str_track(argv[3]))
      err = provenance_secctx_track(argv[2]);
    else if( is_str_delete(argv[3]))
      err = provenance_secctx_delete(argv[2]);

    if(err < 0)
      perror("Could not change security context filter.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_CGROUP_FILTER){
    CHECK_ATTR_NB(argc, 4);
    if( is_str_propagate( argv[3]) )
      err = provenance_cgroup_propagate(strtoul(argv[2], NULL, 0));
    else if( is_str_track(argv[3]))
      err = provenance_cgroup_track(strtoul(argv[2], NULL, 0));
    else if( is_str_delete(argv[3]))
      err = provenance_cgroup_delete(strtoul(argv[2], NULL, 0));

    if(err < 0)
      perror("Could not change CGroup filter.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_USER_FILTER){
    CHECK_ATTR_NB(argc, 4);
    if( is_str_propagate( argv[3]) )
      err = provenance_user_propagate(argv[2]);
    else if( is_str_track(argv[3]))
      err = provenance_user_track(argv[2]);
    else if( is_str_delete(argv[3]))
      err = provenance_user_delete(argv[2]);

    if(err < 0)
      perror("Could not change user filter.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_GROUP_FILTER){
    CHECK_ATTR_NB(argc, 4);
    if( is_str_propagate( argv[3]) )
      err = provenance_group_propagate(argv[2]);
    else if( is_str_track(argv[3]))
      err = provenance_group_track(argv[2]);
    else if( is_str_delete(argv[3]))
      err = provenance_group_delete(argv[2]);

    if(err < 0)
      perror("Could not change group filter.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_FILTER_NODE){
    CHECK_ATTR_NB(argc, 4);
    id = node_str_to_id(argv[2], 256);
    if(id == 0){
      printf("Error invalid node type\n");
      exit(-1);
    }
    if(is_str_true(argv[3]))
      err = provenance_add_node_filter(id);
    else
      err = provenance_remove_node_filter(id);

    if(err < 0)
      perror("Could not change filter settings for this file.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_FILTER_EDGE){
    CHECK_ATTR_NB(argc, 4);
    id = relation_str_to_id(argv[2], 256);
    if(id == 0){
      printf("Error invalid relation type\n");
      exit(-1);
    }
    if(is_str_true(argv[3]))
      err = provenance_add_relation_filter(id);
    else
      err = provenance_remove_relation_filter(id);

    if(err < 0)
      perror("Could not change filter settings for this file.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_PROPAGATE_FILTER_NODE){
    CHECK_ATTR_NB(argc, 4);
    id = node_str_to_id(argv[2], 256);
    if(id == 0){
      printf("Error invalid node type\n");
      exit(-1);
    }
    if(is_str_true(argv[3]))
      err = provenance_add_propagate_node_filter(id);
    else
      err = provenance_remove_propagate_node_filter(id);

    if(err < 0)
      perror("Could not change propagation settings for this file.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_PROPAGATE_FILTER_EDGE){
    CHECK_ATTR_NB(argc, 4);
    id = relation_str_to_id(argv[2], 256);
    if(id == 0){
      printf("Error invalid relation type\n");
      exit(-1);
    }
    if(is_str_true(argv[3]))
      err = provenance_add_propagate_relation_filter(id);
    else
      err = provenance_remove_propagate_relation_filter(id);

    if(err < 0)
      perror("Could not change propagation settings for this file.\n");
    return 0;
  }
  MATCH_ARGS(argv[1], ARG_FILTER_RESET){
    err = provenance_reset_node_filter();
    if(err < 0)
      perror("Could not reset the filters.\n");
    err = provenance_reset_propagate_node_filter();
    if(err < 0)
      perror("Could not reset the filters.\n");
    err = provenance_reset_relation_filter();
    if(err < 0)
      perror("Could not reset the filters.\n");
    err = provenance_reset_propagate_relation_filter();
    if(err < 0)
      perror("Could not reset the filters.\n");
    return 0;
  }
  usage();
  return 0;
}
