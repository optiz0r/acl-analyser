var aa = {

    init: function() {
        aa.generate();
    },

    generate: function() {
        $('#input_update').busy();
        $('#input_update').attr('disabled', true);

        $(['acls','objects','groups','services']).each(function(i,f) {
            aa._priv[f].reset();
            aa._priv[f].generate();
        });

        $('#input_update').attr('disabled', false);
        $('#input_update').busy('hide');
    },

    _priv: {

        acls: { /*{{{*/
            columns: [
                'Access List',
                'Line',
                'Type',
                'Action',
                'Protocol',
                'Source Type',
                'Source Address',
                'Source Mask',
                'Destination Type',
                'Destination Address',
                'Destination Mask',
                'Port Type',
                'Ports/Range',
                'Hits',
                'Enabled',
                'Code',
            ],

            generate: function() {
                // Process each line of the input
                $('#input_config').val().split(/\n/).forEach(function(element, index, array) {
                    aa._priv.acls.appendLine(aa._priv.acls.process.line(element));
                });
            },

            process: {

                line: function(line) { /*{{{*/
                    // Ignore anything that doesn't look like an access-list entry
                    if (! line.match(/^access-list/)) {
                        return false;
                    }

                    // Ignore the preamble
                    if (line.match(/^access-list (?:mode|cached)/)) {
                        return false;
                    }

                    // Ignore the header of any interface
                    if (line.match(/^access-list [a-zA-Z0-9_]+; \d+ elements/)) {
                        return false;
                    }

                    // Strip out the access-list header
                    line = line.replace(/^access-list /, '');

                    // Split the line into fields
                    var fields = line.split(/ /);

                    for (var i = 0; i < fields.length; ++i) {
                        switch (aa._priv.acls.columns[i]) {
                            case 'Line': {
                                if (fields[i] == 'line') {
                                    // Remove the field containing 'line'
                                    fields.splice(i,1);
                                } else {
                                    // This is most likely output from show run, not show access-list
                                    ui.showError('#output_acls');
                                }
                            } break;

                            case 'Type': {
                                // Ignore any comments in the ruleset
                                if (fields[i] == 'remark') {
                                    return false;
                                }
                            } break;

                            case 'Source Type':
                            case 'Destination Type': {
                                switch (fields[i]) {
                                    case 'any': {
                                        // Insert empty address and mask fields
                                        fields.splice(i+1, 0, '', '');
                                    } break;

                                    case 'host': {
                                        // Insert a /32 mask after the address field
                                        fields.splice(i+2, 0, '255.255.255.255');
                                    } break;

                                    case 'object-group': {
                                        // Insert an empty mask after the address field
                                        fields.splice(i+2, 0, '');
                                    } break;

                                    case 'eq':
                                    case 'range': {
                                        // No destination set
                                        fields.splice(i, 0, '', '', '');
                                    } break;

                                    default: {
                                        // Network definition
                                        // Insert a type field here
                                        fields.splice(i, 0, 'subnet');
                                    } break;
                                }
                            } break;

                            case 'Port Type': {
                                switch (fields[i]) {
                                    case 'eq': {
                                        // Do nothing
                                    } break;

                                    case 'object-group': {
                                        // This rule wont have any hit counts
                                        fields.splice(i+2, 0, '');
                                    } break;

                                    case 'range': {
                                        // Collapse the next two fields into a single range field
                                        fields.splice(i+1, 2, fields[i+1] + '-' + fields[i+2]);
                                    } break;

                                    default: {
                                        // No ports are used for this rule, skip the two port columns
                                        fields.splice(i, 0, '', '');
                                    } break;
                                }
                            } break;

                            case 'Hits': {
                                if (fields[i] == 'inactive') {
                                    // Remove this field
                                    fields.splice(i, 1);
                                }

                                if (fields[i] == 'log') {
                                    // Not yet supported, skip the following four rows.
                                    fields.splice(i, 4);
                                }

                                if (fields[i].match(/^0x/)) {
                                    // There's no hitcount for this rule
                                    fields.splice(i, 0, '');
                                } else {
                                    fields[i] = fields[i].replace(/\(hitcnt=(\d+)\)/, "$1");
                                }
                            } break;

                            case 'Enabled': {
                                if (fields[i].match(/^0x/)) {
                                    // This rule is active
                                    fields.splice(i, 0, 'active');
                                }
                            } break;
                        }
                    }
                    
                    return fields.join("\t");
                },

            }, /*}}}*/

            reset: function() {
                $('#output_acls').val('');
                ui.clearErrors($('#output_acls'));
            },

            appendLine: function(line) {
                if (! line) {
                    return;
                }

                $('#output_acls').val(
                    $('#output_acls').val() +
                    line +
                    "\n"
                );
            },
        }, /*}}}*/

        objects: { /*{{{*/
            columns: [
                'Address',
                'Name',
                'Description',
            ],

            generate: function() {
                // Process each line of the input
                $('#input_config').val().split(/\n/).forEach(function(element, index, array) {
                    aa._priv.objects.appendLine(aa._priv.objects.process.line(element));
                });

            },

            process: {
                line: function(line) {
                    if (! line.match(/^name /)) {
                        return false;
                    }

                    fields = line.match(/^name ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)) ([a-zA-Z0-9\._-]+)(?: description (.*))?$/);
                    return [fields[2], fields[1], fields[3]].join("\t");
                },
            },

            reset: function() {
                $('#output_objects').val('');
                ui.clearErrors($('#output_objects'));
            },

            appendLine: function(line) {
                if (! line) {
                    return;
                }

                $('#output_objects').val(
                    $('#output_objects').val() +
                    line +
                    "\n"
                );
            },
        },/*}}}*/

        groups: {/*{{{*/
            columns: [
                'Name',
                'Address',
                'Mask',
            ],

            generate: function() {
                // Process each line of the input
                $('#input_config').val().split(/\n/).forEach(function(element, index, array) {
                    aa._priv.groups.appendLine(aa._priv.groups.process.line(element));
                });
            },

            process: {
                group: '',

                line: function(line) {
                    if (! line.match(/^(object-group network|\s+network-object)/)) {
                        return false;
                    }

                    if (fields = line.match(/^object-group network ([a-zA-Z0-9_-]+)/))  {
                        aa._priv.groups.process.group = fields[1];
                    } else {
                        fields = line.replace(/^\s+network-object\s+/, '').split(/ /);

                        fields.unshift(aa._priv.groups.process.group);
                        
                        for (var i = 0; i < fields.length; ++i) {
                            switch (aa._priv.groups.columns[i]) {
                                case 'Address': {
                                    if (fields[i] == 'host') {
                                        fields.splice(i, 2, fields[i+1], '255.255.255.255');
                                    }
                                } break;
                            }
                        }

                        return fields.join("\t");
                    }
                },
            },

            reset: function() {
                $('#output_groups').val('');
                ui.clearErrors($('#output_groups'));
            },

            appendLine: function(line) {
                if (! line) {
                    return;
                }

                $('#output_groups').val(
                    $('#output_groups').val() +
                    line +
                    "\n"
                );
            },
        }, /*}}}*/

        services: { /*{{{*/
            columns: [
                'Name',
                'Protocol',
                'Port Type',
                'Port/Range',
            ],

            generate: function() {
                // Process each line of the input
                $('#input_config').val().split(/\n/).forEach(function(element, index, array) {
                    aa._priv.services.appendLine(aa._priv.services.process.line(element));
                });
            },

            process: {
                group: '',
                protocol: '',

                line: function(line) {
                    if (! line.match(/^(object-group service|\s+port-object)/)) {
                        return false;
                    }

                    if (fields = line.match(/^object-group service ([a-zA-Z0-9_-]+) ([a-z]+)/))  {
                        aa._priv.services.process.group = fields[1];
                        aa._priv.services.process.protocol = fields[2];
                    } else {
                        fields = line.replace(/^\s+port-object\s+/, '').split(/ /);

                        fields.unshift(aa._priv.services.process.protocol);
                        fields.unshift(aa._priv.services.process.group);

                        for (var i = 0; i < fields.length; ++i) {
                            switch (aa._priv.services.columns[i]) {
                                case 'Port Type': {
                                    if (fields[i] == 'range') {
                                        // The following fields should be squashed into a single
                                        // range field
                                        fields.splice(i+1, 2, fields[i+1] + ' - ' + fields[i+2]);
                                    }
                                } break;
                            }
                        }

                        return fields.join("\t");

                    }
                },
            },

            reset: function() {
                $('#output_services').val('');
                ui.clearErrors($('#output_services'));
            },

            appendLine: function(line) {
                if (!line) {
                    return;
                }

                $('#output_services').val(
                    $('#output_services').val() +
                    line +
                    "\n"
                );
            },
        },/*}}}*/
    },

};

var ui = {
    
    init: function() {
        // Setup handlers for UI events
        $('#input_config').change(function() {
            if ($('#input_autoupdate').attr('checked')) {
                aa.generate(); 
            }
        });

        $(window).resize(function() {
          $().busy("reposition");
        });
        $().busy("preload");
        
        $('#input_update').click(function() {
            aa.generate();
        });
    },

    clearErrors: function(field) {
        $(field).removeClass('error');
    },
    
    showError: function(field) {
        $(field).addClass('error');
    },

};

// Initialise the generator when the page loads
$("document").ready(function(){
   aa.init();
   ui.init();
});


